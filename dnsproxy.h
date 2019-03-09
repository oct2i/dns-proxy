/*
  **
  ** dnsproxy.h
  **
  ** About: Caching Dns proxy
  ** Author: oct2i <oct2i@yandex.ru>
  ** Data: april/may 2015
  ** This software is licensed under the terms of the GNU GPL version 2.
  **
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/ip.h>

#define DNS_SERVER_PORT   53
#define UPD_HDRLEN         8
#define DNS_HDRLEN        12
#define DNS_ANSWLEN       16
#define DNS_Q_CONSTLEN     4   /* Constant sized fields struct _QUESTION */
#define DNS_A_OFFSET       2   /* Offset in association with DNS packet compression */
#define QNAME_MAXLEN      63
#define CONSTMAGIC         1

/* Filling fields hash table 'key' and 'value' */
#define FLAG_FILLING_0     0   /* Filling zero fields */
#define FLAG_FILLING_1     1   /* Filling one field 'key' */
#define FLAG_FILLING_2     2   /* Filling two fields 'key' and 'value' */

#define HASHTAB_SIZE    8192

static unsigned short DNSH_ID;
static unsigned int   DNSA_ANCOUNT;

/******************* NETFILTER FUNCTIONS *******************/
static unsigned int hook_post(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));

static unsigned int hook_pre(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *));

/******************* NETFILTER STRUCTURS *******************/
static struct nf_hook_ops HOOK_POST = {
	.hook     = (void *)hook_post,
	.owner    = THIS_MODULE,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops HOOK_PRE = {
	.hook     = (void *)hook_pre,
	.owner    = THIS_MODULE,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};


/******************* DNS STRUCTURS *******************/
/* Structure of Header DNS */
struct HEADER
{
	unsigned short id;       // identification number

	/******* flags ********/
	unsigned char qr     :1; // query/response flag
	unsigned char opcode :4; // purpose of message
	unsigned char aa     :1; // authoritive answer
	unsigned char tc     :1; // truncated message
	unsigned char rd     :1; // recursion desired
	unsigned char ra     :1; // recursion available
	unsigned char z      :1; // its z! reserved
	unsigned char ad     :1; // authenticated data
	unsigned char cd     :1; // checking disabled
	unsigned char rcode  :4; // response code
	/**********************/

	unsigned short qd_count; // number of question entries
	unsigned short an_count; // number of answer entries
	unsigned short ns_count; // number of authority entries
	unsigned short ar_count; // number of resource entries
};

/* Constant sized fields of Question structure */
struct _QUESTION
{
	unsigned short q_type;
	unsigned short q_class;
};

/* Structure of a Question DNS */
struct QUESTION
{
	unsigned char    *q_name;
	struct _QUESTION *question;
};

/* Constant sized fields of Answer structure */
struct _ANSWER
{
	unsigned short type;
	unsigned short _class;
	unsigned int   ttl;       // number of seconds
	unsigned short rd_length; // length field rdata
};

/* Structure of a Answer DNS */
struct ANSWER
{
	unsigned char  *name;
	struct _ANSWER *answer;
	unsigned char  *rdata;
};


/******************* HASH TABLE STRUCTURS *******************/
/* Hash table slot */
struct NODE
{
	unsigned char *key;
	void          *value;
	unsigned int   key_len;
	unsigned int   value_len;

	struct NODE   *next;
};

/* Data node hash table */
struct DATA_NODE
{
	unsigned int  flag;
	struct NODE  *node;
};

/* Declaration hash table*/
static struct NODE *hashtab[HASHTAB_SIZE];

/******************* HASH TABLE FUNCTIONS *******************/
static unsigned int rs_hash(unsigned char *str, unsigned int len);
static void hashtab_init(struct NODE **hashtab);
static struct DATA_NODE hashtab_lookup(struct NODE **hashtab,
                                       struct QUESTION *dnsq,
                                       unsigned int dnsqlen);
static void hashtab_add_key(struct NODE **hashtab,
                            struct QUESTION *dnsq,
                            unsigned int dnsqlen);
static void hashtab_add_value(struct NODE *node,
                              struct ANSWER *dnsa,
                              unsigned int dnsalen);

/******************* DNS DATA FUNCTIONS *******************/
static unsigned int get_datalen_question(struct QUESTION *dnsq);
static unsigned int get_datalen_answer(void);
static void send_reply_dnspacket(struct sk_buff *in_skb,
                                    unsigned int dst_ip,
                                    unsigned int dst_port,
                                    unsigned int src_ip,
                                    struct NODE *node);

