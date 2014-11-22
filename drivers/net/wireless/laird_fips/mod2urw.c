/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/cdev.h>

#include "laird_i.h"
#include "moddebug.h"
#include "touser.h"
#include "mod2urw.h"
#include "mod2ufn.h"

static int cmd_to_host(char __user * buf, size_t count);
static int cmd_from_host(const char __user * buf, size_t count);
static void cmd_set_state(int enabled);

/*======================================================================*/
static int mod2urw_close(struct inode *inode, struct file *filp)
{
	cmd_set_state(0);
	return 0;
}

static int mod2urw_open(struct inode *inode, struct file *filp)
{
	/* TBD: prevent multiple instances */
	cmd_set_state(1);
	return 0;
}

static DECLARE_WAIT_QUEUE_HEAD(wq_read);
static unsigned short mod2urw_read_ready;

static void __mod2urw_read_wake(void)
{
	mod2urw_read_ready = 1;
	wake_up_interruptible(&wq_read);	/* update poll status */
}

static ssize_t mod2urw_read(struct file *filp, char __user * buf, size_t count,
		       loff_t * f_pos)
{
	int res;
	/* TBD: device mutex ? */
	while (1) {
		mod2urw_read_ready = 0;
		res = cmd_to_host(buf, count);
		if (res != 0)
			break;
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(wq_read, mod2urw_read_ready))
			return -ERESTARTSYS;
	}
	return res;
}

static ssize_t mod2urw_write(struct file *filp, const char __user * buf,
			size_t count, loff_t * f_pos)
{
	cmd_from_host(buf, count);
	return count;
}

static const struct file_operations mod2urw_fops = {
	.open = mod2urw_open,
	.release = mod2urw_close,
	.write = mod2urw_write,
	.read = mod2urw_read,
};

/* use device file /dev/sdc2u0 */
static int mod2urw_major = 0;
static int mod2urw_minor = 0;
static int mod2urw_nr_devs = 1;	/* number of bare devices */
struct mod2urw_dev {
	struct cdev cdev;	/* Char device structure */
};
static struct mod2urw_dev *mod2urw_devices;	/* allocated in mod2urw_init_module */
#define MYDEVSTR	"sdc2u"

/*
 * The cleanup function is used to handle initialization failures as well.
 * Thefore, it must be careful to work correctly even if some of the items
 * have not been initialized
 */
void mod2urw_cleanup_module(void)
{
	int i;
	dev_t devno = MKDEV(mod2urw_major, mod2urw_minor);

	/* Get rid of our char dev entries */
	if (mod2urw_devices) {
		for (i = 0; i < mod2urw_nr_devs; i++) {
			cdev_del(&mod2urw_devices[i].cdev);
		}
		kfree(mod2urw_devices);
	}

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, mod2urw_nr_devs);
}

/*
 * Set up the char_dev structure for this device.
 */
static void mod2urw_setup_cdev(struct mod2urw_dev *dev, int index)
{
	int err, devno = MKDEV(mod2urw_major, mod2urw_minor + index);

	cdev_init(&dev->cdev, &mod2urw_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &mod2urw_fops;
	err = cdev_add(&dev->cdev, devno, 1);
	/* Fail gracefully if need be */
	if (err)
		printk(KERN_NOTICE "Error %d adding mydev%d", err, index);
}

static int mod2urw_init_module(void)
{
	int result, i;
	dev_t dev = 0;

	/*
	 * Get a range of minor numbers to work with, asking for a dynamic
	 * major unless directed otherwise at load time.
	 */
	if (mod2urw_major) {
		dev = MKDEV(mod2urw_major, mod2urw_minor);
		result = register_chrdev_region(dev, mod2urw_nr_devs, MYDEVSTR);
	} else {
		result = alloc_chrdev_region(&dev, mod2urw_minor, mod2urw_nr_devs,
					     MYDEVSTR);
		mod2urw_major = MAJOR(dev);
	}
	if (result < 0) {
		printk(KERN_WARNING "mydev: can't get major %d\n", mod2urw_major);
		return result;
	}

	/*
	 * allocate the devices -- we can't have them static, as the number
	 * can be specified at load time
	 */
	mod2urw_devices = kmalloc(mod2urw_nr_devs * sizeof(struct mod2urw_dev), GFP_KERNEL);
	if (!mod2urw_devices) {
		result = -ENOMEM;
		goto fail;	/* Make this more graceful */
	}
	memset(mod2urw_devices, 0, mod2urw_nr_devs * sizeof(struct mod2urw_dev));

	/* Initialize each device. */
	for (i = 0; i < mod2urw_nr_devs; i++) {
		mod2urw_setup_cdev(&mod2urw_devices[i], i);
	}

	return 0;		/* succeed */

fail:
	mod2urw_cleanup_module();
	return result;
}

/* driver register data -- pointer to functions */
#define VERSION_STRING "1.0"

/* initialization */
static int __init sdclkm_init(void)
{
	printk(KERN_INFO "%s.ko: version %s\n", MYDEVSTR, VERSION_STRING);
	if (mod2urw_init_module() < 0)
		goto failure;
	return 0;
failure:
	return -1;
}

/* cleanup and exit */
static void __exit sdclkm_exit(void)
{
	mod2urw_cleanup_module();
}

module_init(sdclkm_init);
module_exit(sdclkm_exit);

MODULE_AUTHOR("Laird");
MODULE_DESCRIPTION("Laird fips userland interface");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(VERSION_STRING);

/*======================================================================*/
/*======================================================================*/

/* command control */
typedef struct cmd_ctl_s {
	cmd_hdr_t hdr;		/* command header to pass to user space */
	int hdr_len;		/* length of command header adjusted for numitems */
	const cmd_def_t *def;
	item_ptr_t itp[MAXIT];	/* pointers to the kernel data items */
	sdclkm_cb_t cbd;	/* callback function and callback data */
	struct cmd_ctl_s *next;
} cmd_ctl_t;

/* queue of cmd submitted for processing */
static struct {
	int enabled;		/* set when user-space app registers */
	cmd_ctl_t *active;
	cmd_ctl_t *first;
	cmd_ctl_t *last;
} cmd_glob;

/* spinlock to protect the queue of pending requests */
static DEFINE_SPINLOCK(cmdq_lock);

static inline cmd_ctl_t *cmd_ctl_alloc(void)
{
	cmd_ctl_t *ctl;		/* command control */
	ctl = kmalloc(sizeof(*ctl), GFP_ATOMIC);
	return ctl;
}

static inline void cmd_ctl_free(cmd_ctl_t * ctl)
{
	kfree(ctl);
}

/* note, this function may be called at process, or bottom half level
 * called at bh level from driver transmit/receive processing
 */
static int cmd_ctl_submit(cmd_ctl_t * ctl)
{
	ctl->next = NULL;
	spin_lock_bh(&cmdq_lock);
	if (!cmd_glob.enabled) {
		/* no user-space module to process command, fail it */
		spin_unlock_bh(&cmdq_lock);
		cmd_ctl_free(ctl);
		return -1;
	}
	if (cmd_glob.last) {
		cmd_glob.last->next = ctl;
	} else {
		cmd_glob.first = ctl;
	}
	cmd_glob.last = ctl;
	spin_unlock_bh(&cmdq_lock);
	__mod2urw_read_wake();
	return 0;
}

/* called only at process level in read */
static cmd_ctl_t *cmd_ctl_get_next(void)
{
	cmd_ctl_t *ctl;
	spin_lock_bh(&cmdq_lock);
	ctl = cmd_glob.first;
	if (ctl) {
		cmd_glob.first = ctl->next;
		if (cmd_glob.first == NULL) {
			cmd_glob.last = NULL;
		}
	}
	cmd_glob.active = ctl;
	spin_unlock_bh(&cmdq_lock);
	return ctl;
}

/* called only at process level in write */
static cmd_ctl_t *cmd_ctl_get_active(void)
{
	/* don't need spinlock here */
	return cmd_glob.active;
}

static void cmd_ctl_free_active(void)
{
	if (cmd_glob.active) {
		cmd_ctl_free(cmd_glob.active);
		cmd_glob.active = NULL;
	}
}

/* copies available command into host buffer
 * returns total length of data, -Exxx on fail, 0 if no data available
 */
static int cmd_to_host(char __user * buf, size_t count)
{
	cmd_ctl_t *ctl;
	cmd_hdr_t *hdr;
	const cmd_def_t *def;
	int i;
	int err = 0;

	ctl = cmd_ctl_get_next();
	if (!ctl) {
		return 0;	/* no command to pass to user space */
	}

	def = ctl->def;
	hdr = &ctl->hdr;
	if (count < hdr->len) {
		printk(KERN_ALERT "%s: buffer too small\n", __FUNCTION__);
		return -EFBIG;	/* insufficient space */
	}

	/* copy header to the buffer */
	err = copy_to_user((void __user *)buf, hdr, ctl->hdr_len);
	/* copy each data item to the buffer */
	for (i = 0; i < def->numit && !err; i++) {
		if ((def->flags[i] & ITEM_TO_HOST) == 0)
			continue;
		if (hdr->it[i].len == 0)
			continue;
		err = copy_to_user((void __user *)&buf[hdr->it[i].offset],
				   ctl->itp[i].p, hdr->it[i].len);
	}
	/* return length of the data */
	if (err)
		return -EFAULT;
	return hdr->len;
}

static inline int __skb_from_user(struct sk_buff *skb,
				  const char __user * buf,
				  int oldoff, int newoff, int newlen)
{
	int headchg, tailchg;
	int headroom, tailroom;
	headchg = oldoff - newoff;
	tailchg = newlen - skb->len - headchg;

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);
	if (headroom < headchg) {
		printk(KERN_ALERT "\n<%s: headroom %d, need %d>\n",
		       __FUNCTION__, headroom, headchg);
		return -1;
	}

	if (skb_tailroom(skb) < tailchg) {
		printk(KERN_ALERT "\n<%s: tailroom %d, need %d>\n",
		       __FUNCTION__, tailroom, tailchg);
		return -1;
	}
	if (headchg > 0) {
		skb_push(skb, headchg);		/* add to head */
	} else if (headchg < 0) {
		skb_pull(skb, -headchg);	/* remove from head */
	}
	if (tailchg > 0) {
		skb_put(skb, tailchg);		/* add to tail */
	} else if (tailchg < 0) {
		skb_trim(skb, newlen);		/* remove from tail */
	}
	return copy_from_user(skb->data, (void __user *)&buf[newoff], newlen);
}

static int cmd_from_host(const char __user * buf, size_t count)
{
	cmd_ctl_t *ctl;
	cmd_hdr_t *hdr;
	const cmd_def_t *def;
	cmd_hdr_t cin;
	int i;
	int res;
	int err = 0;

	ctl = cmd_ctl_get_active();
	if (!ctl) {
		printk(KERN_ALERT "%s: ERROR!! unsolicited cmd\n",
		       __FUNCTION__);
		return 0;
	}

	def = ctl->def;
	hdr = &ctl->hdr;
	if (count != hdr->len) {
		printk(KERN_ALERT "%s: ERROR!! incorrect response length\n",
		       __FUNCTION__);
		printk(KERN_ALERT "%s: len %d; but, expected %d\n",
		       __FUNCTION__, count, hdr->len);
		res = -1;
	} else {
		/* copy the result from the header */
		err = copy_from_user(&cin, (void __user *)buf, ctl->hdr_len);
		res = cin.res;
		/* copy each data item from the buffer */
		for (i = 0; i < def->numit && !err; i++) {
			if ((def->flags[i] & ITEM_FROM_HOST) == 0)
				continue;
			if (hdr->it[i].len == 0)
				continue;
			if ((def->flags[i] & ITEM_SKB) != 0) {
				/* both offset and length may have changed... */
				err = __skb_from_user(ctl->itp[i].skb, buf,
						      hdr->it[i].offset,
						      cin.it[i].offset,
						      cin.it[i].len);
				/* TBD: if necessary to change skb, then must pass back in ctl->cbd.pdata */
				continue;
			}
			err = copy_from_user(ctl->itp[i].p,
					     (void __user *)&buf[hdr->it[i].
								 offset],
					     hdr->it[i].len);
		}
	}
	/* if an error occurred, ensure failure result is passed back */
	if (err)
		res = -1;
	/* call the callback function to indicate command is complete */
	(*(ctl->cbd.pfn)) (ctl->cbd.pdata, res);
	/* release the command control structure */
	cmd_ctl_free_active();
	return 0;
}

/* user-space app has exitted -- fail all commands */
static void cmd_fail_all(void)
{
	cmd_ctl_t *ctl;
	do {
		ctl = cmd_ctl_get_active();
		if (!ctl)
			ctl = cmd_ctl_get_next();
		if (ctl) {
			printk(KERN_ALERT "%s: cancel in progress command\n",
			       __FUNCTION__);
			/* call the callback function to indicate command is complete */
			(*(ctl->cbd.pfn)) (ctl->cbd.pdata, -1);
			/* release the command control structure */
			cmd_ctl_free_active();
		}
	} while (ctl);
}

/* set enabled when user-space processing is available */
static void cmd_set_state(int enabled)
{
	spin_lock_bh(&cmdq_lock);
	cmd_glob.enabled = enabled;
	spin_unlock_bh(&cmdq_lock);
	if (!enabled) {
		cmd_fail_all();	/* fail all in progress commands */
	}
}

/* default callback where caller can wait for completion
 * create callback data
 */
typedef struct {
	struct mutex m;
	int res;
} defcb_data;

/* callback function when operation completes */
static void callback_wait(void *din, int res)
{
	defcb_data *data = (defcb_data *) din;
	/* save result */
	data->res = res;
	/* signal the waiting thread */
	mutex_unlock(&data->m);
}

/* does a cmd_submit() and then waits for completion using above callback
 * can only be used if caller may wait -- user level, not softirq/tasklet
 */
static int cmd_ctl_submit_and_wait(cmd_ctl_t * ctl)
{
	defcb_data *data;
	int res;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);
	if (!data) {
		printk(KERN_ALERT "%s: alloc failed\n", __FUNCTION__);
		cmd_ctl_free(ctl);	/* release the control structure */
		return -ENOMEM;
	}
	/* initialize the mutex in the locked state */
	mutex_init(&data->m);
	mutex_lock(&data->m);
	/* set the callback fields in the control structure and submit */
	ctl->cbd.pfn = callback_wait;
	ctl->cbd.pdata = data;
	res = cmd_ctl_submit(ctl);
	if (res) {
		/* failed to submit -- fail it now
		 * do not free ctl, released in cmd_ctl_submit()
		 */
		kfree(data);
		return res;
	}
	/* wait for callback to complete and unlock mutex */
	if (mutex_lock_interruptible(&data->m)) {
		/* this case will not occur with drivers, only with test utility
		 * so not important to deal with immediately
		 * TBD: deal with this case!!!!
		 */
		printk(KERN_ALERT "%s: interrupted!!!\n", __FUNCTION__);
		return -1;
	}
	/* fetch the result */
	res = data->res;
	/* free the callback data */
	kfree(data);
	/* do NOT free ctl as it was already freed after the callback was called */
	return res;
}

/* commands to user space are passed in as a command number,
 * and a number of items each consisting of an offset  and length
 * input: def - const command definition
 * input: itp - data items (pointer, length)
 * output: command is enqueued for transfer to user space
 */
int sdclkm_command(sdclkm_cb_t * cbd,
			  const cmd_def_t * def, item_ptr_t * itp)
{
	cmd_ctl_t *ctl;		/* command control */
	cmd_hdr_t *hdr;		/* command header */
	int i;
	int offset;


	ctl = cmd_ctl_alloc();
	if (!ctl) {
		printk(KERN_ALERT "%s: allocation failed\n", __FUNCTION__);
		return -ENOMEM;
	}

	/* save data item pointers */
	memcpy(&ctl->itp, itp, sizeof(*itp) * def->numit);
	/* save the command/item definition */
	ctl->def = def;

	/* build the command header to be passed to user space */
	hdr = &ctl->hdr;
	offset = (u8 *) (&hdr->it[def->numit]) - (u8 *) hdr;
	ctl->hdr_len = offset;
	for (i = 0; i < def->numit; i++) {
		hdr->it[i].len = itp[i].len;
		if (def->flags[i] & ITEM_SKB) {
			/* this item is enclosed in previous item (wrapper) */
			hdr->it[i].offset = hdr->it[i - 1].offset +
			    ((u8 *) itp[i].p - (u8 *) itp[i - 1].p);
		} else {
			hdr->it[i].offset = offset;
			offset += (hdr->it[i].len + 3) & (~3);
		}
	}
	hdr->len = offset;
	hdr->cmd = def->cmd;
	hdr->res = -1;
	hdr->numit = def->numit;

	/* if using callback, submit and let callback get result */
	if (cbd) {
		ctl->cbd = *cbd;
		return cmd_ctl_submit(ctl);
	}

	/* if no callback -- wait for operation to complete and return result */
	return cmd_ctl_submit_and_wait(ctl);
}

