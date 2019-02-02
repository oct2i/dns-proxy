/*
  **
  ** dnsproxy.c
  **
  ** About: DNS proxy caching
  ** Author: oct2i <oct2i@yandex.ru>
  ** Data: april/may 2015
  ** This software is licensed under the terms of the GNU GPL version 2.
  **
*/

#include "dnsproxy.h"

/*
 * Register netfilter module.
 *
 */
static int __init dnsproxy_start(void)
{
	nf_register_hook(&HOOK_POST);
	nf_register_hook(&HOOK_PRE);

	hashtab_init(hashtab);

	printk(KERN_ALERT "Register dnsproxy.\nHashtable size: %d\n",
	                                               HASHTAB_SIZE);
	return 0;
}


/*
 * Unregister netfilter module.
 *
 */
static void __exit dnsproxy_stop(void)
{
	nf_unregister_hook(&HOOK_POST);
	nf_unregister_hook(&HOOK_PRE);

	printk(KERN_ALERT "Unregister dnsproxy.\n");
}


/*
 * Netfilter POST_ROUTING.
 * Intercept Question data sent to the server DNS (port 'XX' -> port '53').
 * Processing data.
 * Return value: NF_ACCEPT or NF_DROP.
 */
static unsigned int hook_post(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *))
{
	struct iphdr     *ip_h;
	struct udphdr    *udp_h;

	struct HEADER    *dns_h;
	struct QUESTION  *dns_q;
	//struct _QUESTION *dns__q;

	struct DATA_NODE  dnode;

	unsigned int dns_q_qnamelen = 0;

	//ETHERNET
	if (skb->protocol == htons(ETH_P_IP)) {
		ip_h = ip_hdr(skb);

		//UDP
		if (ip_h->protocol == IPPROTO_UDP) {
			udp_h = (void *)(struct updhdr *)skb_transport_header(skb);

			if (udp_h->dest == ntohs(DNS_SERVER_PORT)) {
				/*
				printk(KERN_ALERT "--UDP dns-packet POST: %u -> %u\n",
				        ntohs(udp_h->source),
				        ntohs(udp_h->dest));
				*/
				//DNS HEADER
				dns_h = (struct HEADER *)
				        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN);
				/*
				printk(KERN_ALERT "DNS HEADER\n--ID=%u\n--QR=%u\n--QDCount=%u\n--ANCount=%u\n",
				        ntohs(dns_h->id), (dns_h->qr),
				        ntohs(dns_h->qd_count),
				        ntohs(dns_h->an_count));
				*/
				DNSH_ID = ntohs(dns_h->id);

				//DNS QUESTION
				dns_q = (struct QUESTION *)
				        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN);

				dns_q_qnamelen = get_datalen_question(dns_q);
				if (dns_q_qnamelen <= 0) {
					return NF_ACCEPT;
				}

				/*
				printk(KERN_ALERT "domain name: ");
				for (i = 0; i < bufflen; i++) {
					printk(KERN_ALERT "%c", buff[i]);
				}
				*/

				/*
				dns__q = (struct _QUESTION *)
				         (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
				          dns_q_qnamelen);
				printk(KERN_ALERT "DNS QUESTION\n--QName=%s\n--QType=%u\n--QClass=%u\n\n",
								dns_q,
				        ntohs(dns__q->q_type),
				        ntohs(dns__q->q_class));
				*/

				dnode = hashtab_lookup(hashtab, dns_q, dns_q_qnamelen);

				if (dnode.flag == FLAG_FILLING_0) {
					hashtab_add_key(hashtab, dns_q, dns_q_qnamelen);
				}
				else if ( (dnode.flag == FLAG_FILLING_2) && (dnode.node != NULL) ) {
					send_reply_dnspacket(skb, ip_h->saddr, \
					                          udp_h->source, \
					                          ip_h->daddr, dnode.node);

					printk(KERN_ALERT "** SEND REPLY DNS PACKET **\n");

					return NF_DROP;
				}
			}
		}
	}
	return NF_ACCEPT;
}


/*
 * Netfilter PRE_ROUTING.
 * Intercept Answer data sent from the server DNS (port 'XX' <- port '53').
 * Processing data.
 * Return value: NF_ACCEPT.
 */
static unsigned int hook_pre(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
	struct iphdr     *ip_h;
	struct udphdr    *udp_h;

	struct HEADER    *dns_h;
	struct QUESTION  *dns_q;
	//struct _QUESTION *dns__q;
	struct ANSWER    *dns_a;
	struct _ANSWER   *dns__a;

	struct DATA_NODE  dnode;

	unsigned int dns_q_qnamelen = 0;
	unsigned int dns_a_len = 0;

	//ETHERNET
	if (skb->protocol == htons(ETH_P_IP)) {
		ip_h = ip_hdr(skb);

		//UDP
		if (ip_h->protocol == IPPROTO_UDP) {
			udp_h = (void *)(struct updhdr *)skb_transport_header(skb);

			if (udp_h->source == ntohs(DNS_SERVER_PORT)) {
				/*
				printk(KERN_ALERT "--UDP dns-packet PRE: %u <- %u\n",
				        ntohs(udp_h->dest),
				        ntohs(udp_h->source));
				*/
				//DNS HEADER
				dns_h = (struct HEADER *)
				        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN);
				/*
				printk(KERN_ALERT "DNS HEADER\n--ID=%u\n--QR=%u\n--QDCount=%u\n--ANCount=%u\n",
				        ntohs(dns_h->id), dns_h->qr,
				        ntohs(dns_h->qd_count),
				        ntohs(dns_h->an_count));
				*/
				DNSA_ANCOUNT = ntohs(dns_h->an_count);

				//DNS QUESTION
				dns_q = (struct QUESTION *)
				        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN);

				dns_q_qnamelen = get_datalen_question(dns_q);
				if (dns_q_qnamelen <= 0) {
					return NF_ACCEPT;
				}

				/*
				dns__q = (struct _QUESTION *)
				         (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
				          dns_q_qnamelen);
				printk(KERN_ALERT "DNS QUESTION\n--QName=%s\n--QType=%u\n--QClass=%u\n",
								dns_q,
				        ntohs(dns__q->q_type),
				        ntohs(dns__q->q_class));
				*/

				//DNS ANSWER
				dns__a = (struct _ANSWER *)
				         (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
				         (dns_q_qnamelen + DNS_Q_CONSTLEN) + DNS_A_OFFSET);
				/*
				printk(KERN_ALERT "DNS ANSWER\n--Type=%u\n--Class=%u\n--TTL=%d\n--RDLen=%u\n\n",
				        ntohs(dns__a->type),
				        ntohs(dns__a->_class), dns__a->ttl,
				        ntohs(dns__a->rd_length));
				*/

				//Pointer on DNS ANSWER
				dns_a = (struct ANSWER *)
				        (skb->data + (ip_h->ihl * 4) + UPD_HDRLEN + DNS_HDRLEN +
				        (dns_q_qnamelen + DNS_Q_CONSTLEN));

				dns_a_len = get_datalen_answer();
				if (dns_a_len <= 0) {
					return NF_ACCEPT;
				}

				dnode = hashtab_lookup(hashtab, dns_q, dns_q_qnamelen);

				if ( (dnode.flag == FLAG_FILLING_1) && (dnode.node != NULL) ) {
					hashtab_add_value(dnode.node, dns_a, dns_a_len);
				}
			}
		}
	}
	return NF_ACCEPT;
}


/*
 * Get length Question DNS.
 * Parsing domain name and counting length.
 * Return value: length field 'q_name'.
 */
static unsigned int get_datalen_question(struct QUESTION *dnsq)
{
	unsigned char *buff;
	unsigned int   i;
	unsigned int   index = 0;
	unsigned int   bufflen = 1;

	buff = (unsigned char *)kmalloc(bufflen, GFP_KERNEL);
	memset(buff, 0, bufflen);
	memcpy(buff, dnsq, bufflen);

	for ( ; (unsigned int)buff[index] != 0; ) {
	// while ( (unsigned int)buff[index] != 0 ) {

		for (i = 1; i <= (QNAME_MAXLEN + 1); i++) {
			if ((unsigned int)buff[index] == i) {
				bufflen += i;
				bufflen++;
				index = bufflen;
				index--;
				break;
			}
		}

		if (i == (QNAME_MAXLEN + 1)) {
			printk(KERN_ERR "\nERROR: length domain name more '63' symbols\n\n");
			kfree(buff);
			return -1;
		}

		buff = (unsigned char *)kmalloc(bufflen, GFP_KERNEL);
		memset(buff, 0, bufflen);
		memcpy(buff, dnsq, bufflen);
	}

	if ( (index == 0) && ((unsigned int)buff[index] == 0) ) {
		printk(KERN_ERR "\nERROR: length domain name is equal '0' symbols\n\n");
		kfree(buff);
		return -1;
	}

	kfree(buff);
	return bufflen;
}


/*
 * Get length Answer DNS.
 * Counting length.
 * Return value: length section Answer.
 */
static unsigned int get_datalen_answer(void)
{
	return (DNS_ANSWLEN * (DNSA_ANCOUNT + CONSTMAGIC));
}


/*
 * Sending a response packet DNS.
 * The formation of the packet.
 * Sending packet routing circuit.
 * Return value: no.
 *
 */
static void send_reply_dnspacket(struct sk_buff *in_skb,
                                    unsigned int dst_ip,
                                    unsigned int dst_port,
                                    unsigned int src_ip,
                                    struct NODE *node)
{
	struct sk_buff   *nskb;
	struct iphdr     *ip_h;
	struct udphdr    *udp_h;

	struct HEADER    *dns_h;
	struct _QUESTION *dns__q;

	unsigned char    *data_q;
	void             *data_a;

	unsigned int dns_q_len;
	unsigned int dns_a_len;
	unsigned int udp_len;

	dns_q_len = (node->key_len);
	dns_a_len = (node->value_len);
	udp_len   = (UPD_HDRLEN + DNS_HDRLEN + dns_q_len + dns_a_len);

	nskb = alloc_skb(sizeof(struct iphdr) + udp_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb) {
		printk (KERN_ERR "ERROR! Allocate memory to DNS reply\n");
		return;
	}

	skb_reserve(nskb, LL_MAX_HEADER);
	skb_reset_network_header(nskb);

	//IP HEADER
	ip_h = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	ip_h->version  = 4;
	ip_h->ihl      = sizeof(struct iphdr) / 4;
	ip_h->ttl      = 64;
	ip_h->tos      = 0;
	ip_h->id       = 0;
	ip_h->frag_off = htons(IP_DF);
	ip_h->protocol = IPPROTO_UDP;
	ip_h->saddr    = src_ip;
	ip_h->daddr    = dst_ip;
	ip_h->tot_len  = htons(sizeof(struct iphdr) + udp_len);
	ip_h->check    = 0;
	ip_h->check    = ip_fast_csum((unsigned char *)ip_h, ip_h->ihl);

	//UDP HEADER
	udp_h = (struct udphdr *)skb_put(nskb, UPD_HDRLEN);
	memset(udp_h, 0, sizeof(*udp_h));
	udp_h->source = htons(DNS_SERVER_PORT);
	udp_h->dest   = dst_port;
	udp_h->len    = htons(udp_len);

	//DNS HEADER
	dns_h = (struct HEADER *)skb_put(nskb, DNS_HDRLEN);
	dns_h->id       = (unsigned short) htons(DNSH_ID);
	dns_h->qr       = 0;
	dns_h->opcode   = 0;
	dns_h->aa       = 0;
	dns_h->tc       = 0;
	dns_h->rd       = 1;
	dns_h->ra       = 0;
	dns_h->z        = 0;
	dns_h->ad       = 0;
	dns_h->cd       = 0;
	dns_h->rcode    = 0;
	dns_h->qd_count = htons(1);
	dns_h->an_count = htons(DNSA_ANCOUNT);
	dns_h->ns_count = 0;
	dns_h->ar_count = 0;

	skb_dst_set(nskb, dst_clone(skb_dst(in_skb)));
	nskb->protocol = htons(ETH_P_IP);

	//DNS QUESTION field 'q_name'
	data_q = (char *)skb_put(nskb, dns_q_len);
	memcpy(data_q, (node->key), dns_q_len);

	//DNS QUESTION fields 'q_type' and 'q_class'
	dns__q = (struct _QUESTION *)skb_put(nskb, DNS_Q_CONSTLEN);
	dns__q->q_type  = htons(1);
	dns__q->q_class = htons(1);

	//DNS ANSWER
	data_a = (void *)skb_put(nskb, dns_a_len);
	memcpy(data_a, (node->value), dns_a_len);

	//UDP HEADER continuation
	udp_h->check  = 0;
	udp_h->check  = csum_tcpudp_magic(src_ip, dst_ip,
	                                 udp_len, IPPROTO_UDP,
	                                 csum_partial(udp_h, udp_len, 0));

	if (ip_route_me_harder(nskb, RTN_UNSPEC)) {
		printk (KERN_ERR "\nERROR: fail function ip_route_me_harder()\n");
		kfree_skb(nskb);
	}

	ip_local_out(nskb);
	return;
}


/*
 * Hash function for type data 'unsigned char'.
 * Return the hash value of the function is the
 * address of a cell in the main memory, which
 * will be located on a pair of (key, value).
 *
 */
static unsigned int rs_hash(unsigned char *str, unsigned int len)
{
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; i < len; str++, i++) {
		hash = hash * a + (unsigned char)(*str);
		a *= b;
	}
	return (hash % HASHTAB_SIZE);
}


/*
 * Initialization hash table.
 */
static void hashtab_init(struct NODE **hashtab)
{
	unsigned int i;

	for (i = 0; i < HASHTAB_SIZE; i++) {
		hashtab[i] = NULL;
	}
}


/*
 * Lookup slot in hash table.
 * Return 'struct DATA_NODE' contains fields 'flag' and 'ptr on node'.
 *
 */
static struct DATA_NODE hashtab_lookup(struct NODE **hashtab,
                                       struct QUESTION *dnsq,
                                       unsigned int dnsqlen)
{
	unsigned char *key;
	unsigned int   index = 0;

	struct NODE   *node;

	struct DATA_NODE dnode = {
		.flag = FLAG_FILLING_0,
		.node = NULL,
	};

	key = (unsigned char *)kmalloc(dnsqlen, GFP_KERNEL);
	memset(key, 0, dnsqlen);
	memcpy(key, dnsq, dnsqlen);

	index = rs_hash(key, dnsqlen);

	for (node = hashtab[index];
			 node != NULL;
			 node = node->next)
	{
		if (memcmp(node->key, key, dnsqlen) == 0) {
			dnode.flag = FLAG_FILLING_1;
			dnode.node = node;
			if (node->value_len != 0) {
				dnode.flag = FLAG_FILLING_2;
			}
		}
	}
	/*
	printk(KERN_ALERT "\n*** RESULT = %d\n", dnode.flag);
	*/

	kfree(key);
	return dnode;
}


/*
 * Creation hash table slot.
 * Addition data 'question' i.e.'key'.
 */
static void hashtab_add_key(struct NODE **hashtab,
                            struct QUESTION *dnsq,
                            unsigned int dnsqlen)
{
	unsigned char *key;
	unsigned int   index = 0;

	struct NODE   *node;

	key = (unsigned char *)kmalloc(dnsqlen, GFP_KERNEL);
	memset(key, 0, dnsqlen);
	memcpy(key, dnsq, dnsqlen);

	index = rs_hash(key, dnsqlen);

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (node != NULL) {
		node->key       = key;
		node->key_len   = dnsqlen;
		node->value_len = 0;
		node->next      = hashtab[index];
		hashtab[index]  = node;
	}
	/*
	printk(KERN_ALERT "\n~~~ add node->key\n");
	*/
}


/*
 * Addition hash table slot data 'answer' i.e. 'value'.
 */
static void hashtab_add_value(struct NODE *node,
                              struct ANSWER *dnsa,
                              unsigned int dnsalen)
{
	void *value;

	value = (void *)kmalloc(dnsalen, GFP_KERNEL);
	memset(value, 0, dnsalen);
	memcpy(value, dnsa, dnsalen);

	node->value     = value;
	node->value_len = dnsalen;
	/*
	printk (KERN_ALERT "\n~~~ add node->value\n");
	*/
}

module_init(dnsproxy_start);
module_exit(dnsproxy_stop);

MODULE_AUTHOR("oct2i");
MODULE_DESCRIPTION("DNS proxy caching");
MODULE_LICENSE("GPLv2");

