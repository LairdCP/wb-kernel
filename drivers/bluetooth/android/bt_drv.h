/** @file bt_drv.h
 *  @brief This header file contains global constant/enum definitions,
 *  global variable declaration.
 *
 *
 *  Copyright 2014-2020 NXP
 *
 *  This software file (the File) is distributed by NXP
 *  under the terms of the GNU General Public License Version 2, June 1991
 *  (the License).  You may use, redistribute and/or modify the File in
 *  accordance with the terms and conditions of the License, a copy of which
 *  is available by writing to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 *  worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 *  THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 *  ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 *  this warranty disclaimer.
 *
 */

#ifndef _BT_DRV_H_
#define _BT_DRV_H_

#ifndef DEBUG_LEVEL1
#define DEBUG_LEVEL1
#endif

#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>

#ifdef __SDIO__
#define SDIO_SUSPEND_RESUME
#endif //__SDIO__

#include "hci_wrapper.h"

#define FPNUM "26"

/** MAX adapter BT driver supported */
#define MAX_BT_ADAPTER    3

#ifndef BIT
/** BIT definition */
#define BIT(x) (1UL << (x))
#endif

#ifdef __LP64__
typedef u64 t_ptr;
#else
typedef u32 t_ptr;
#endif

/** max number of adapter supported */
#define MAX_BT_ADAPTER      3
/** Define drv_mode bit */
#define DRV_MODE_BT         BIT(0)

/** Define devFeature bit */
#define DEV_FEATURE_BT     BIT(0)
#define DEV_FEATURE_BTAMP     BIT(1)
#define DEV_FEATURE_BLE     BIT(2)

/** Define maximum number of radio func supported */
#define MAX_RADIO_FUNC     4

/** MAC address print format */
#ifndef MACSTR
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

/** MAC address print arguments */
#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

/** Debug level : Message */
#define	DBG_MSG			BIT(0)
/** Debug level : Fatal */
#define DBG_FATAL		BIT(1)
/** Debug level : Error */
#define DBG_ERROR		BIT(2)
/** Debug level : Data */
#define DBG_DATA		BIT(3)
/** Debug level : Command */
#define DBG_CMD			BIT(4)
/** Debug level : Event */
#define DBG_EVENT		BIT(5)
/** Debug level : Interrupt */
#define DBG_INTR		BIT(6)

/** Debug entry : Data dump */
#define DBG_DAT_D		BIT(16)
/** Debug entry : Data dump */
#define DBG_CMD_D		BIT(17)

/** Debug level : Entry */
#define DBG_ENTRY		BIT(28)
/** Debug level : Warning */
#define DBG_WARN		BIT(29)
/** Debug level : Informative */
#define DBG_INFO		BIT(30)

#ifdef	DEBUG_LEVEL1
extern u32 mbt_drvdbg;

#ifdef	DEBUG_LEVEL2
/** Print informative message */
#define	PRINTM_INFO(msg...)  \
	do {if (mbt_drvdbg & DBG_INFO)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print warning message */
#define	PRINTM_WARN(msg...) \
	do {if (mbt_drvdbg & DBG_WARN)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print entry message */
#define	PRINTM_ENTRY(msg...) \
	do {if (mbt_drvdbg & DBG_ENTRY) \
		printk(KERN_DEBUG msg); } while (0)
#else
/** Print informative message */
#define	PRINTM_INFO(msg...)  do {} while (0)
/** Print warning message */
#define	PRINTM_WARN(msg...)  do {} while (0)
/** Print entry message */
#define	PRINTM_ENTRY(msg...) do {} while (0)
#endif /* DEBUG_LEVEL2 */

/** Print interrupt message */
#define	PRINTM_INTR(msg...)  \
	do {if (mbt_drvdbg & DBG_INTR)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print event message */
#define	PRINTM_EVENT(msg...) \
	do {if (mbt_drvdbg & DBG_EVENT) \
		printk(KERN_DEBUG msg); } while (0)
/** Print command message */
#define	PRINTM_CMD(msg...)   \
	do {if (mbt_drvdbg & DBG_CMD)   \
		printk(KERN_DEBUG msg); } while (0)
/** Print data message */
#define	PRINTM_DATA(msg...)  \
	do {if (mbt_drvdbg & DBG_DATA)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print error message */
#define	PRINTM_ERROR(msg...) \
	do {if (mbt_drvdbg & DBG_ERROR) \
		printk(KERN_ERR msg); } while (0)
/** Print fatal message */
#define	PRINTM_FATAL(msg...) \
	do {if (mbt_drvdbg & DBG_FATAL) \
		printk(KERN_ERR msg); } while (0)
/** Print message */
#define	PRINTM_MSG(msg...)   \
	do {if (mbt_drvdbg & DBG_MSG)   \
		printk(KERN_ALERT msg); } while (0)

/** Print data dump message */
#define	PRINTM_DAT_D(msg...)  \
	do {if (mbt_drvdbg & DBG_DAT_D)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print data dump message */
#define	PRINTM_CMD_D(msg...)  \
	do {if (mbt_drvdbg & DBG_CMD_D)  \
		printk(KERN_DEBUG msg); } while (0)

/** Print message with required level */
#define	PRINTM(level, msg...) PRINTM_##level(msg)

/** Debug dump buffer length */
#define DBG_DUMP_BUF_LEN	64
/** Maximum number of dump per line */
#define MAX_DUMP_PER_LINE	16
/** Maximum data dump length */
#define MAX_DATA_DUMP_LEN	48

/**
 * @brief Prints buffer data upto provided length
 *
 * @param prompt          Char pointer
 * @param buf			  Buffer
 * @param len    		  Length
 *
 * @return                N/A
 */
static inline void
hexdump(char *prompt, u8 *buf, int len)
{
	int i;
	char dbgdumpbuf[DBG_DUMP_BUF_LEN];
	char *ptr = dbgdumpbuf;

	printk(KERN_DEBUG "%s: len=%d\n", prompt, len);
	for (i = 1; i <= len; i++) {
		ptr += snprintf(ptr, 4, "%02x ", *buf);
		buf++;
		if (i % MAX_DUMP_PER_LINE == 0) {
			*ptr = 0;
			printk(KERN_DEBUG "%s\n", dbgdumpbuf);
			ptr = dbgdumpbuf;
		}
	}
	if (len % MAX_DUMP_PER_LINE) {
		*ptr = 0;
		printk(KERN_DEBUG "%s\n", dbgdumpbuf);
	}
}

/** Debug hexdump of debug data */
#define DBG_HEXDUMP_DAT_D(x, y, z) \
	do {if (mbt_drvdbg & DBG_DAT_D) \
		hexdump(x, y, z); } while (0)
/** Debug hexdump of debug command */
#define DBG_HEXDUMP_CMD_D(x, y, z) \
	do {if (mbt_drvdbg & DBG_CMD_D) \
		hexdump(x, y, z); } while (0)

/** Debug hexdump */
#define	DBG_HEXDUMP(level, x, y, z)    DBG_HEXDUMP_##level(x, y, z)

/** Mark entry point */
#define	ENTER()			PRINTM(ENTRY, "Enter: %s, %s:%i\n", __func__, \
							__FILE__, __LINE__)
/** Mark exit point */
#define	LEAVE()			PRINTM(ENTRY, "Leave: %s, %s:%i\n", __func__, \
							__FILE__, __LINE__)
#else
/** Do nothing */
#define	PRINTM(level, msg...) do {} while (0)
/** Do nothing */
#define DBG_HEXDUMP(level, x, y, z)    do {} while (0)
/** Do nothing */
#define	ENTER()  do {} while (0)
/** Do nothing */
#define	LEAVE()  do {} while (0)
#endif /* DEBUG_LEVEL1 */

/** Bluetooth upload size */
#define	BT_UPLD_SIZE				2312
/** Bluetooth status success */
#define BT_STATUS_SUCCESS			(0)
/** Bluetooth status pending */
#define BT_STATUS_PENDING           (1)
/** Bluetooth status failure */
#define BT_STATUS_FAILURE			(-1)

#ifndef	TRUE
/** True value */
#define TRUE			1
#endif
#ifndef	FALSE
/** False value */
#define	FALSE			0
#endif

/** Set thread state */
#define OS_SET_THREAD_STATE(x)		set_current_state(x)
/** Time to wait until Host Sleep state change in millisecond */
#define WAIT_UNTIL_HS_STATE_CHANGED 2000
/** Time to wait cmd resp in millisecond */
#define WAIT_UNTIL_CMD_RESP	    5000

/** Sleep until a condition gets true or a timeout elapses */
#define os_wait_interruptible_timeout(waitq, cond, timeout) \
	wait_event_interruptible_timeout(waitq, cond, ((timeout) * HZ / 1000))

#define os_wait_timeout(waitq, cond, timeout) \
         wait_event_timeout(waitq, cond, ((timeout) * HZ / 1000))

/** bt thread structure */
typedef struct {
	/** Task */
	struct task_struct *task;
	/** Queue */
	wait_queue_head_t waitQ;
	/** PID */
	pid_t pid;
	/** Private structure */
	void *priv;
} bt_thread;

/**
 * @brief Activates bt thread
 *
 * @param thr			  A pointer to bt_thread structure
 *
 * @return                N/A
 */
static inline void
bt_activate_thread(bt_thread *thr)
{
	/** Initialize the wait queue */
	init_waitqueue_head(&thr->waitQ);

	/** Record the thread pid */
	thr->pid = current->pid;
}

/**
 * @brief De-activates bt thread
 *
 * @param thr			  A pointer to bt_thread structure
 *
 * @return                N/A
 */
static inline void
bt_deactivate_thread(bt_thread *thr)
{
	thr->pid = 0;
	return;
}

/**
 * @brief Creates bt thread
 *
 * @param btfunc          Function pointer
 * @param thr			  A pointer to bt_thread structure
 * @param name    		  Char pointer
 *
 * @return                N/A
 */
static inline void
bt_create_thread(int (*btfunc) (void *), bt_thread *thr, char *name)
{
	thr->task = kthread_run(btfunc, thr, "%s", name);
}

/**
 * @brief Delete bt thread
 *
 * @param thr			  A pointer to bt_thread structure
 *
 * @return                N/A
 */
static inline int
bt_terminate_thread(bt_thread *thr)
{
	/* Check if the thread is active or not */
	if (!thr->pid)
		return -1;

	kthread_stop(thr->task);
	return 0;
}

/**
 * @brief  Set scheduled timeout
 *
 * @param millisec		 Time unit in ms
 *
 * @return                N/A
 */
static inline void
os_sched_timeout(u32 millisec)
{
	set_current_state(TASK_INTERRUPTIBLE);

	schedule_timeout((millisec * HZ) / 1000);
}

#ifndef __ATTRIB_ALIGN__
#define __ATTRIB_ALIGN__ __attribute__((aligned(4)))
#endif

#ifndef __ATTRIB_PACK__
#define __ATTRIB_PACK__ __attribute__((packed))
#endif

/** BT histogram command */
#define BT_CMD_HISTOGRAM            0xEA
/** max antenna num */
#define MAX_ANTENNA_NUM             2
/** BDR 1M */
#define BDR_RATE_1M					1
/** EDR 2/3 M */
#define EDR_RATE_2_3M			    2
/** BLE 1M */
#define BLE_RATE_1M                 5
/** max bt link number */
#define MAX_BT_LINK                 10
/** max ble link number */
#define MAX_BLE_LINK                16

/** BT link state structure */
typedef struct _bt_link_stat {
    /** txrx rate 1: BDR_1M, 2:EDR 2/3 M, 3:BLE 1M */
	u8 txrxrate;
    /** power: -30 = N = 20 dbm*/
	s8 txpower;
    /** rssi: -127 to +20 (For BT), -128 to +127 (For BLE) */
	s8 rssi;
} __ATTRIB_PACK__ bt_link_stat;

/** BT histogram data structure */
typedef struct _bt_histogram_data {
	/** Antenna */
	u8 antenna;
	/** Powerclass */
	u8 powerclass;
	/** bt link state structure */
	bt_link_stat link[MAX_BT_LINK + MAX_BLE_LINK];
} __ATTRIB_PACK__ bt_histogram_data;

/** BT histogram proc data structure */
typedef struct _bt_hist_proc_data {
    /** antenna */
	u8 antenna;
	/** Private structure */
	struct _bt_private *pbt;
} bt_hist_proc_data;

/** Data structure for the NXP Bluetooth device */
typedef struct _bt_dev {
	/** device name */
	char name[DEV_NAME_LEN];
	/** card pointer */
	void *card;
	/** IO port */
	u32 ioport;
	/** m_dev structure */
	struct m_dev m_dev[MAX_RADIO_FUNC];

	/** Tx download ready flag */
	u8 tx_dnld_rdy;
	/** Function */
	u8 fn;
	/** Rx unit */
	u8 rx_unit;
	/** Power Save mode : Timeout configuration */
	u16 idle_timeout;
	/** Power Save mode */
	u8 psmode;
	/** Power Save command */
	u8 pscmd;
	/** Host Sleep mode */
	u8 hsmode;
	/** Host Sleep command */
	u8 hscmd;
	/** Low byte is gap, high byte is GPIO */
	u16 gpio_gap;
	/** Host Sleep configuration command */
	u8 hscfgcmd;
	/** Host Send Cmd Flag		 */
	u8 sendcmdflag;
	/** opcode for Send Cmd */
	u16 send_cmd_opcode;
	/** Device Type			*/
	u8 devType;
	/** Device Features    */
	u8 devFeature;
#ifdef __SDIO__
	/** cmd52 function */
	u8 cmd52_func;
	/** cmd52 register */
	u8 cmd52_reg;
	/** cmd52 value */
	u8 cmd52_val;
	/** SDIO pull control command */
	u8 sdio_pull_ctrl;
	/** Low 2 bytes is pullUp, high 2 bytes for pull-down */
	u32 sdio_pull_cfg;
#endif //__SDIO__
	/** Test mode command */
	u8 test_mode;
} bt_dev_t, *pbt_dev_t;

/** NXP bt adapter structure */
typedef struct _bt_adapter {
	/** Chip revision ID */
	u8 chip_rev;
#ifdef __SDIO__
    /** magic val */
	u8 magic_val;
#endif //__SDIO__
	/** Surprise removed flag */
	u8 SurpriseRemoved;
	/** IRQ number */
	int irq;
	/** Interrupt counter */
	u32 IntCounter;
	/** Tx packet queue */
	struct sk_buff_head tx_queue;

	/** Pointer of fw dump file name */
	char *fwdump_fname;
	/** Pending Tx packet queue */
	struct sk_buff_head pending_queue;
	/** tx lock flag */
	u8 tx_lock;
	/** Power Save mode */
	u8 psmode;
	/** Power Save state */
	u8 ps_state;
	/** Host Sleep state */
	u8 hs_state;
	/** hs skip count */
	u32 hs_skip;
	/** suspend_fail flag */
	u8 suspend_fail;
	/** suspended flag */
	u8 is_suspended;
	/** Number of wakeup tries */
	u8 WakeupTries;
	/** Host Sleep wait queue */
	wait_queue_head_t cmd_wait_q __ATTRIB_ALIGN__;
	/** Host Cmd complet state */
	u8 cmd_complete;
	/** indicate using wait event timeout */
	u8 wait_event_timeout;
#ifdef __SDIO__
	/** last irq recv */
	u8 irq_recv;
	/** last irq processed */
	u8 irq_done;
	/** sdio int status */
	u8 sd_ireg;
     /** buf allocated for transmit */
	u8 *tx_buffer;
    /** buf for transmit */
	u8 *tx_buf;
    /** buf allocated for read interrupt status */
	u8 *hw_regs_buf;
    /** buf for read interrupt status */
	u8 *hw_regs;
#endif //__SDIO__
	/** tx pending */
	u32 skb_pending;
/** Version string buffer length */
#define MAX_VER_STR_LEN         128
	/** Driver version */
	u8 drv_ver[MAX_VER_STR_LEN];
	/** Number of command timeout */
	u32 num_cmd_timeout;
} bt_adapter, *pbt_adapter;

/** Length of prov name */
#define PROC_NAME_LEN				32

/** Item data structure */
struct item_data {
	/** Name */
	char name[PROC_NAME_LEN];
	/** Size */
	u32 size;
	/** Address */
	t_ptr addr;
	/** Offset */
	u32 offset;
	/** Flag */
	u32 flag;
};

/** Proc private data structure */
struct proc_private_data {
	/** Name */
	char name[PROC_NAME_LEN];
	/** File flag */
	u32 fileflag;
	/** Buffer size */
	u32 bufsize;
	/** Number of items */
	u32 num_items;
	/** Item data */
	struct item_data *pdata;
	/** Private structure */
	struct _bt_private *pbt;
	/** File operations */
	const struct proc_ops *fops;
};

/** Device proc structure */
struct device_proc {
	/** Proc directory entry */
	struct proc_dir_entry *proc_entry;
    /** proc entry for hist */
	struct proc_dir_entry *hist_entry;
	/** num of proc files */
	u8 num_proc_files;
	/** pointer to proc_private_data */
	struct proc_private_data *pfiles;
};

/** Private structure for the MV device */
typedef struct _bt_private {
	/** Bluetooth device */
	bt_dev_t bt_dev;
	/** Adapter */
	bt_adapter *adapter;
	/** Firmware helper */
	const struct firmware *fw_helper;
	/** Firmware */
	const struct firmware *firmware;
	/** Init user configure file */
	const struct firmware *init_user_cfg;
	/** Init user configure wait queue token */
	u16 init_user_conf_wait_flag;
	/** Init user configure file wait queue */
	wait_queue_head_t init_user_conf_wait_q __ATTRIB_ALIGN__;
	/** Firmware request start time */
	struct timespec64 req_fw_time;
	/** Hotplug device */
	struct device *hotplug_device;
	/** thread to service interrupts */
	bt_thread MainThread;
	 /** proc data */
	struct device_proc dev_proc[MAX_RADIO_FUNC];
	/** Driver lock */
	spinlock_t driver_lock;
	/** Driver lock flags */
	ulong driver_flags;
	/** Driver reference flags */
	struct kobject kobj;
	int debug_device_pending;
	int debug_ocf_ogf[2];
#ifdef __SDIO__
	u8 fw_reload;
#endif //__SDIO__
	/* hist_data_len */
	u8 hist_data_len;
    /** hist data */
	bt_histogram_data hist_data[MAX_ANTENNA_NUM];
    /** hist proc data */
	bt_hist_proc_data hist_proc[MAX_ANTENNA_NUM];
#ifdef BLE_WAKEUP
	u8 ble_wakeup_buf_size;
	u8 *ble_wakeup_buf;
    /** white list address: address count + count* address*/
	u8 white_list[61];
#endif
    /** fw dump state */
	u8 fw_dump;
} bt_private, *pbt_private;

int bt_get_histogram(bt_private *priv);

/** Disable interrupt */
#define OS_INT_DISABLE	spin_lock_irqsave(&priv->driver_lock, \
						priv->driver_flags)
/** Enable interrupt */
#define	OS_INT_RESTORE	spin_unlock_irqrestore(&priv->driver_lock, \
						priv->driver_flags)

#ifndef HCI_BT_AMP
/** BT_AMP flag for device type */
#define  HCI_BT_AMP		0x80
#endif

/** Device type of BT */
#define DEV_TYPE_BT		0x00
/** Device type of AMP */
#define DEV_TYPE_AMP		0x01

/** NXP vendor packet */
#define MRVL_VENDOR_PKT			0xFE

/** Bluetooth command : Get FW Version */
#define BT_CMD_GET_FW_VERSION       0x0F
/** Bluetooth command : Sleep mode */
#define BT_CMD_AUTO_SLEEP_MODE		0x23
/** Bluetooth command : Host Sleep configuration */
#define BT_CMD_HOST_SLEEP_CONFIG	0x59
/** Bluetooth command : Host Sleep enable */
#define BT_CMD_HOST_SLEEP_ENABLE	0x5A
/** Bluetooth command : Module Configuration request */
#define BT_CMD_MODULE_CFG_REQ		0x5B
#ifdef BLE_WAKEUP
/** Bluetooth command : Get whitelist */
#define BT_CMD_GET_WHITELIST        0x9C

#define HCI_BLE_GRP_BLE_CMDS                 0x08
#define HCI_BT_SET_EVENTMASK_OCF           0x0001
#define HCI_BLE_ADD_DEV_TO_WHITELIST_OCF     0x0011
#define HCI_BLE_SET_SCAN_PARAMETERS_OCF      0x000B
#define HCI_BLE_SET_SCAN_ENABLE_OCF          0x000C

#endif
/** Bluetooth command : PMIC Configure */
#define BT_CMD_PMIC_CONFIGURE           0x7D

#ifdef __SDIO__
/** Bluetooth command : SDIO pull up down configuration request */
#define BT_CMD_SDIO_PULL_CFG_REQ	0x69
#endif //__SDIO__
/** Bluetooth command : Set Evt Filter Command */
#define BT_CMD_SET_EVT_FILTER		0x05
/** Bluetooth command : Enable Write Scan Command */
#define BT_CMD_ENABLE_WRITE_SCAN	0x1A
/** Bluetooth command : Enable Device under test mode */
#define BT_CMD_ENABLE_DEVICE_TESTMODE	0x03
/** Sub Command: Module Bring Up Request */
#define MODULE_BRINGUP_REQ		0xF1
/** Sub Command: Module Shut Down Request */
#define MODULE_SHUTDOWN_REQ		0xF2
/** Module already up */
#define MODULE_CFG_RESP_ALREADY_UP      0x0c
/** Sub Command: Host Interface Control Request */
#define MODULE_INTERFACE_CTRL_REQ	0xF5

/** Bluetooth event : Power State */
#define BT_EVENT_POWER_STATE		0x20

/** Bluetooth Power State : Enable */
#define BT_PS_ENABLE			0x02
/** Bluetooth Power State : Disable */
#define BT_PS_DISABLE			0x03
/** Bluetooth Power State : Sleep */
#define BT_PS_SLEEP			0x01
/** Bluetooth Power State : Awake */
#define BT_PS_AWAKE			0x02

/** Vendor OGF */
#define VENDOR_OGF				0x3F
/** OGF for reset */
#define RESET_OGF		0x03
/** Bluetooth command : Reset */
#define BT_CMD_RESET	0x03

/** Host Sleep activated */
#define HS_ACTIVATED			0x01
/** Host Sleep deactivated */
#define HS_DEACTIVATED			0x00

/** Power Save sleep */
#define PS_SLEEP			0x01
/** Power Save awake */
#define PS_AWAKE			0x00

/** bt header length */
#define BT_HEADER_LEN			4

#ifndef MAX
/** Return maximum of two */
#define MAX(a, b)		((a) > (b) ? (a) : (b))
#endif

/** This is for firmware specific length */
#define EXTRA_LEN	36

/** Command buffer size for NXP driver */
#define MRVDRV_SIZE_OF_CMD_BUFFER       (2 * 1024)

/** Bluetooth Rx packet buffer size for NXP driver */
#define MRVDRV_BT_RX_PACKET_BUFFER_SIZE \
	(HCI_MAX_FRAME_SIZE + EXTRA_LEN)

#ifdef __SDIO__
/** Buffer size to allocate */
#define ALLOC_BUF_SIZE	(((MAX(MRVDRV_BT_RX_PACKET_BUFFER_SIZE, \
			MRVDRV_SIZE_OF_CMD_BUFFER) + SDIO_HEADER_LEN \
			+ SD_BLOCK_SIZE - 1) / SD_BLOCK_SIZE) * SD_BLOCK_SIZE)
#else // __SDIO__
#define ALLOC_BUF_SIZE	(MAX(MRVDRV_BT_RX_PACKET_BUFFER_SIZE, \
			MRVDRV_SIZE_OF_CMD_BUFFER) + BT_HEADER_LEN)
#endif // __SDIO__

/** Request FW timeout in second */
#define REQUEST_FW_TIMEOUT		30

/** The number of times to try when polling for status bits */
#define MAX_POLL_TRIES			100

/** The number of times to try when waiting for downloaded firmware to
    become active when multiple interface is present */
#define MAX_MULTI_INTERFACE_POLL_TRIES  150

/** The number of times to try when waiting for downloaded firmware to
     become active. (polling the scratch register). */
#define MAX_FIRMWARE_POLL_TRIES		100

/** default idle time */
#define DEFAULT_IDLE_TIME           1000

#define BT_CMD_HEADER_SIZE    3

#define BT_CMD_DATA_LEN    128
#define BT_EVT_DATA_LEN    8

/** BT command structure */
typedef struct _BT_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** Data */
	u8 data[BT_CMD_DATA_LEN];
} __ATTRIB_PACK__ BT_CMD;

/** BT event structure */
typedef struct _BT_EVENT {
	/** Event Counter */
	u8 EC;
	/** Length */
	u8 length;
	/** Data */
	u8 data[BT_EVT_DATA_LEN];
} BT_EVENT;

#if defined(SDIO_SUSPEND_RESUME)
#define DEF_GPIO_GAP        0xffff
#else
#define DEF_GPIO_GAP        0x0d64
#endif

#ifdef BLE_WAKEUP
#define BD_ADDR_SIZE 6
/** Vendor specific event */
#define VENDOR_SPECIFIC_EVENT     0xff
/** system suspend event */
#define HCI_SYSTEM_SUSPEND_EVT    0x80
/** system suspend */
#define HCI_SYSTEM_SUSPEND        0x00
/** system resume */
#define HCI_SYSTEM_RESUME         0x01
/** This function enables ble wake up pattern */
int bt_config_ble_wakeup(bt_private *priv, bool is_shutdown);
int bt_send_system_event(bt_private *priv, u8 flag);
void bt_send_hw_remove_event(bt_private *priv);
#endif

/** This function verify the received event pkt */
int check_evtpkt(bt_private *priv, struct sk_buff *skb);

/* Prototype of global function */
/** This function gets the priv reference */
struct kobject *bt_priv_get(bt_private *priv);
/** This function release the priv reference */
void bt_priv_put(bt_private *priv);
/** This function adds the card */
bt_private *bt_add_card(void *card);
/** This function removes the card */
int bt_remove_card(void *card);
/** This function handles the interrupt */
void bt_interrupt(struct m_dev *m_dev);

/** This function creates proc interface directory structure */
int bt_root_proc_init(void);
/** This function removes proc interface directory structure */
int bt_root_proc_remove(void);
/** This function initializes proc entry */
int bt_proc_init(bt_private *priv, struct m_dev *m_dev, int seq);
/** This function removes proc interface */
void bt_proc_remove(bt_private *priv);

/** This function process the received event */
int bt_process_event(bt_private *priv, struct sk_buff *skb);
/** This function enables host sleep */
int bt_enable_hs(bt_private *priv, bool is_shutdown);
/** This function used to send command to firmware */
int bt_prepare_command(bt_private *priv);
/** This function frees the structure of adapter */
void bt_free_adapter(bt_private *priv);
/** This function handle the receive packet */
void bt_recv_frame(bt_private *priv, struct sk_buff *skb);
void bt_store_firmware_dump(bt_private *priv, u8 *buf, u32 len);

/** clean up m_devs */
void clean_up_m_devs(bt_private *priv);
/** bt driver call this function to register to bus driver */
int *sbi_register(void);
/** bt driver call this function to unregister to bus driver */
void sbi_unregister(void);
/** bt driver calls this function to register the device  */
int sbi_register_dev(bt_private *priv);
/** bt driver calls this function to unregister the device */
int sbi_unregister_dev(bt_private *priv);
/** This function initializes firmware */
int sbi_download_fw(bt_private *priv);
/** Configures hardware to quit deep sleep state */
int sbi_wakeup_firmware(bt_private *priv);
/** Module configuration and register device */
int sbi_register_conf_dpc(bt_private *priv);

/** This function is used to send the data/cmd to hardware */
#ifdef __SDIO__
int sbi_host_to_card(bt_private *priv, u8 *payload, u16 nb);
/** This function reads the current interrupt status register */
int sbi_get_int_status(bt_private *priv);
/** This function enables the host interrupts */
int sbi_enable_host_int(bt_private *priv);
/** This function disables the host interrupts */
int sbi_disable_host_int(bt_private *priv);
#else //__SDIO__
int sbi_host_to_card(bt_private *priv, struct sk_buff *skb);
#endif //__SDIO__

/** bt fw reload flag */
extern int bt_fw_reload;
#ifdef __SDIO__
/** driver initial the fw reset */
#define FW_RELOAD_SDIO_INBAND_RESET   1
/** out band reset trigger reset, no interface re-emulation */
#define FW_RELOAD_NO_EMULATION  2
#endif //__SDIO__
/** out band reset with interface re-emulation */
#define FW_RELOAD_WITH_EMULATION 3
/** This function reload firmware */
void bt_request_fw_reload(bt_private *priv, int mode);

#ifdef __SDIO__
#define MAX_TX_BUF_SIZE     2312
/** This function downloads firmware image to the card */
int sd_download_firmware_w_helper(bt_private *priv);
void bt_dump_sdio_regs(bt_private *priv);
#define FW_DUMP_TYPE_ENDED                    0x002
#define FW_DUMP_TYPE_MEM_ITCM                 0x004
#define FW_DUMP_TYPE_MEM_DTCM                 0x005
#define FW_DUMP_TYPE_MEM_SQRAM                0x006
#define FW_DUMP_TYPE_MEM_IRAM                 0x007
#define FW_DUMP_TYPE_REG_MAC                  0x009
#define FW_DUMP_TYPE_REG_CIU                  0x00E
#define FW_DUMP_TYPE_REG_APU                  0x00F
#define FW_DUMP_TYPE_REG_ICU                  0x014
/* dumps the firmware to /var/ or /data/ */
void bt_dump_firmware_info_v2(bt_private *priv);
#else //__SDIO__
/** This function flushes anchored Tx URBs */
int usb_flush(bt_private *priv);
void usb_free_frags(bt_private *priv);
void usb_char_notify(bt_private *priv, unsigned int arg);
#endif //__SDIO__

/** Max line length allowed in init config file */
#define MAX_LINE_LEN        256
/** Max MAC address string length allowed */
#define MAX_MAC_ADDR_LEN    18
/** Max register type/offset/value etc. parameter length allowed */
#define MAX_PARAM_LEN       12

/** Bluetooth command : Mac address configuration */
#define BT_CMD_CONFIG_MAC_ADDR		0x22
/** Bluetooth command : Write CSU register */
#define BT_CMD_CSU_WRITE_REG		0x66
/** Bluetooth command : Load calibrate data */
#define BT_CMD_LOAD_CONFIG_DATA     0x61
/** Bluetooth command : Load calibrate ext data */
#define BT_CMD_LOAD_CONFIG_DATA_EXT     0x60

/** Bluetooth command : BLE deepsleep */
#define BT_CMD_BLE_DEEP_SLEEP       0x8b

/** BT_BLE command structure */
typedef struct _BT_BLE_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** deepsleep flag */
	u8 deepsleep;
} __ATTRIB_PACK__ BT_BLE_CMD;

/** BT_CSU command structure */
typedef struct _BT_CSU_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** reg type */
	u8 type;
	/** address */
	u8 offset[4];
	/** Data */
	u8 value[2];
} __ATTRIB_PACK__ BT_CSU_CMD;

/** This function sets mac address */
int bt_set_mac_address(bt_private *priv, u8 *mac);
/** This function writes value to CSU registers */
int bt_write_reg(bt_private *priv, u8 type, u32 offset, u16 value);
/** BT set user defined init data and param */
int bt_init_config(bt_private *priv, char *cfg_file);
/** BT PMIC Configure command */
int bt_pmic_configure(bt_private *priv);
/** This function load the calibrate data */
int bt_load_cal_data(bt_private *priv, u8 *config_data, u8 *mac);
/** This function load the calibrate ext data */
int bt_load_cal_data_ext(bt_private *priv, u8 *config_data, u32 cfg_data_len);
/** BT set user defined calibration data */
int bt_cal_config(bt_private *priv, char *cfg_file, char *mac);
/** BT set user defined calibration ext data */
int bt_cal_config_ext(bt_private *priv, char *cfg_file);
int bt_init_mac_address(bt_private *priv, char *mac);

int bt_set_independent_reset(bt_private *priv);
/** Bluetooth command : Independent reset */
#define BT_CMD_INDEPENDENT_RESET     0x0D

/** BT HCI command structure */
typedef struct _BT_HCI_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** cmd type */
	u8 cmd_type;
	/** cmd len */
	u8 cmd_len;
	/** Data */
	u8 data[6];
} __ATTRIB_PACK__ BT_HCI_CMD;

#endif /* _BT_DRV_H_ */
