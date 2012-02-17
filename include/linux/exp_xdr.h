#ifndef _LINUX_EXP_XDR_H
#define _LINUX_EXP_XDR_H

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <linux/string.h>

struct exp_xdr_stream {
	__be32 *p;
	__be32 *end;
};

/**
 * exp_xdr_qwords - Calculate the number of quad-words holding nbytes
 * @nbytes: number of bytes to encode
 */
static inline size_t
exp_xdr_qwords(__u32 nbytes)
{
	return DIV_ROUND_UP(nbytes, 4);
}

/**
 * exp_xdr_qbytes - Calculate the number of bytes holding qwords
 * @qwords: number of quad-words to encode
 */
static inline size_t
exp_xdr_qbytes(size_t qwords)
{
	return qwords << 2;
}

/**
 * exp_xdr_reserve_space - Reserve buffer space for sending
 * @xdr: pointer to exp_xdr_stream
 * @nbytes: number of bytes to reserve
 *
 * Checks that we have enough buffer space to encode 'nbytes' more
 * bytes of data. If so, update the xdr stream.
 */
static inline __be32 *
exp_xdr_reserve_space(struct exp_xdr_stream *xdr, size_t nbytes)
{
	__be32 *p = xdr->p;
	__be32 *q;

	/* align nbytes on the next 32-bit boundary */
	q = p + exp_xdr_qwords(nbytes);
	if (unlikely(q > xdr->end || q < p))
		return NULL;
	xdr->p = q;
	return p;
}

/**
 * exp_xdr_reserve_qwords - Reserve buffer space for sending
 * @xdr: pointer to exp_xdr_stream
 * @nwords: number of quad words (u32's) to reserve
 */
static inline __be32 *
exp_xdr_reserve_qwords(struct exp_xdr_stream *xdr, size_t qwords)
{
	return exp_xdr_reserve_space(xdr, exp_xdr_qbytes(qwords));
}

/**
 * exp_xdr_encode_u32 - Encode an unsigned 32-bit value onto a xdr stream
 * @p: pointer to encoding destination
 * @val: value to encode
 */
static inline __be32 *
exp_xdr_encode_u32(__be32 *p, __u32 val)
{
	*p = cpu_to_be32(val);
	return p + 1;
}

/**
 * exp_xdr_encode_u64 - Encode an unsigned 64-bit value onto a xdr stream
 * @p: pointer to encoding destination
 * @val: value to encode
 */
static inline __be32 *
exp_xdr_encode_u64(__be32 *p, __u64 val)
{
	put_unaligned_be64(val, p);
	return p + 2;
}

/**
 * exp_xdr_encode_bytes - Encode an array of bytes onto a xdr stream
 * @p: pointer to encoding destination
 * @ptr: pointer to the array of bytes
 * @nbytes: number of bytes to encode
 */
static inline __be32 *
exp_xdr_encode_bytes(__be32 *p, const void *ptr, __u32 nbytes)
{
	if (likely(nbytes != 0)) {
		unsigned int qwords = exp_xdr_qwords(nbytes);
		unsigned int padding = exp_xdr_qbytes(qwords) - nbytes;

		memcpy(p, ptr, nbytes);
		if (padding != 0)
			memset((char *)p + nbytes, 0, padding);
		p += qwords;
	}
	return p;
}

/**
 * exp_xdr_encode_opaque - Encode an opaque type onto a xdr stream
 * @p: pointer to encoding destination
 * @ptr: pointer to the opaque array
 * @nbytes: number of bytes to encode
 *
 * Encodes the 32-bit opaque size in bytes followed by the opaque value.
 */
static inline __be32 *
exp_xdr_encode_opaque(__be32 *p, const void *ptr, __u32 nbytes)
{
	p = exp_xdr_encode_u32(p, nbytes);
	return exp_xdr_encode_bytes(p, ptr, nbytes);
}

/**
 * exp_xdr_encode_opaque_qlen - Encode the opaque length onto a xdr stream
 * @lenp: pointer to the opaque length destination
 * @endp: pointer to the end of the opaque array
 *
 * Encodes the 32-bit opaque size in bytes given the start and end pointers
 */
static inline __be32 *
exp_xdr_encode_opaque_len(__be32 *lenp, const void *endp)
{
	size_t nbytes = (char *)endp - (char *)(lenp + 1);

	exp_xdr_encode_u32(lenp, nbytes);
	return lenp + 1 + exp_xdr_qwords(nbytes);
}
#endif /* _LINUX_EXP_XDR_H */
