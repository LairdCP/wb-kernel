/*
 * Copyright (c) 2018, Laird
 *
 */

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fscrypt.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/key.h>
#include <linux/evm.h>
#include <keys/user-type.h>

static struct key *builtin_fs_keys;

struct mem_key {
	u8 key[FSCRYPT_MAX_KEY_SIZE];
};

struct mem_region {
	u32 aux_base;
	void __iomem *virt_base;
	size_t size;
};

static int laird_fs_map_memory(struct mem_region *mem, struct device *dev,
				const char *name, int i)
{
	struct device_node *np;
	struct resource r;
	int ret;

	np = of_parse_phandle(dev->of_node, name, 0);
	if (!np) {
		dev_err(dev, "No %s specified\n", name);
		return -EINVAL;
	}

	ret = of_address_to_resource(np, 0, &r);
	of_node_put(np);
	if (ret)
		return ret;

	mem->aux_base = (u32)r.start;
	mem->size = resource_size(&r);
	mem->virt_base = devm_ioremap_wc(dev, r.start, resource_size(&r));
	if (!mem->virt_base)
		return -ENOMEM;

	return 0;
}

static int laird_fs_insertkey(struct fscrypt_key *fscrypt_key)
{
	key_ref_t key_ref;

	/* create or update the logon key and add it to the target
	 * keyring */
	key_ref = key_create_or_update(make_key_ref(builtin_fs_keys, 1),
						"logon",
						"fscrypt:ffffffffffffffff",
						fscrypt_key,
						sizeof(*fscrypt_key),
						KEY_POS_SEARCH | KEY_USR_SEARCH |
						KEY_POS_LINK | KEY_USR_LINK,
						KEY_ALLOC_IN_QUOTA);
	if (IS_ERR(key_ref))
		return PTR_ERR(key_ref);

	key_ref_put(key_ref);

	return 0;
}

static int laird_fs_keyring_init(void)
{
	builtin_fs_keys =
		keyring_alloc("_builtin_fs_keys",
			      KUIDT_INIT(0), KGIDT_INIT(0), current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			      KEY_USR_VIEW | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL, NULL);
	if (IS_ERR(builtin_fs_keys)) {
		return -ENOMEM;
	}

	return 0;
}

static int laird_fs_probe(struct platform_device *pdev)
{
	int				rc;
	struct mem_key	*key;
	struct mem_region *region;
	struct fscrypt_key fscrypt_key;

	dev_info(&pdev->dev, "In the Laird FS probe\n");

	rc = laird_fs_keyring_init();
	if (rc) {
		dev_err(&pdev->dev, "Can't allocate builtin fs keyring\n");
		return rc;
	}

	region = devm_kzalloc(&pdev->dev, sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	rc = laird_fs_map_memory(region, &pdev->dev, "memory-region", 0);
	if (rc)
		return rc;

	key = region->virt_base;
	fscrypt_key.mode = 0;
	fscrypt_key.size = sizeof(key->key);
	memcpy(fscrypt_key.raw, key->key, sizeof(key->key));
	rc = laird_fs_insertkey(&fscrypt_key);
	if (rc)
		return rc;
#ifdef CONFIG_LAIRD_FS_EVM_KEY
	rc = evm_set_key(key->key, sizeof(key->key));
#endif
	return rc;
}

static const struct of_device_id laird_fs_match_table[] = {
	{ .compatible = "laird,fs_mem", },
	{}
};

static struct platform_driver laird_fs_driver = {
	.driver	= {
		.name		= "laird-fs-mem",
		.of_match_table	= laird_fs_match_table,
	},
	.probe		= laird_fs_probe,
};
builtin_platform_driver(laird_fs_driver);

