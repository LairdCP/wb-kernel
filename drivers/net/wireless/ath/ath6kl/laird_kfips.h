extern bool fips_mode;

extern int laird_data_rx(struct sk_buff **pskb);
extern int laird_data_tx(struct sk_buff **pskb, struct net_device *dev);
extern void laird_addkey(struct net_device *ndev, u8 key_index,
						 bool pairwise,
						 const u8 * mac_addr,
						 const u8 * key, int keylen,
						 const u8 * seq, int seqlen);
extern void laird_delkey(struct net_device *ndev, u8 key_index);
extern void laird_deinit(void);

// helper functions to get to aead functions
#define CCM_AAD_LEN	32
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif
extern int _ccm_encrypt(void *tfm, u8 *b_0, u8 *aad, size_t aad_len,
						u8 *data, size_t data_len, u8 *mic);
extern int _ccm_decrypt(void *tfm, u8 *b_0, u8 *aad, size_t aad_len,
						u8 *data, size_t data_len, u8 *mic);
extern void *_ccm_key_setup_encrypt(const char *alg, const u8 key[],
									size_t key_len, size_t mic_len);
extern void _ccm_key_free(void *_tfm);

