// Minimal pfvar.h for OS-independent compilation.
#ifndef _PFVAR_H_
#define _PFVAR_H_

#include <netinet/in.h>
#include <sys/param.h>

#define PFI_AFLAG_NETWORK	0x01
#define PFI_AFLAG_BROADCAST	0x02
#define PFI_AFLAG_PEER		0x04
#define PFI_AFLAG_MODEMASK	0x07
#define PFI_AFLAG_NOALIAS	0x08

enum	{ PF_ADDR_ADDRMASK, PF_ADDR_NOROUTE, PF_ADDR_DYNIFTL,
	  PF_ADDR_TABLE, PF_ADDR_URPFFAILED,
	  PF_ADDR_RANGE };

#define	PF_TABLE_NAME_SIZE	32

struct pf_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		u_int8_t		addr8[16];
		u_int16_t		addr16[8];
		u_int32_t		addr32[4];
	} pfa;		    /* 128-bit address */
#define v4	pfa.v4
#define v6	pfa.v6
#define addr8	pfa.addr8
#define addr16	pfa.addr16
#define addr32	pfa.addr32
};

struct pf_addr_wrap {
	union {
		struct {
			struct pf_addr		 addr;
			struct pf_addr		 mask;
		}			 a;
		char			 ifname[IFNAMSIZ];
		char			 tblname[PF_TABLE_NAME_SIZE];
	}			 v;
	union {
		struct pfi_dynaddr	*dyn;
		struct pfr_ktable	*tbl;
		int			 dyncnt;
		int			 tblcnt;
	}			 p;
	u_int8_t		 type;		/* PF_ADDR_* */
	u_int8_t		 iflags;	/* PFI_AFLAG_* */
};

struct pf_rule_addr {
	struct pf_addr_wrap	 addr;
	u_int16_t		 port[2];
	u_int8_t		 neg;
	u_int8_t		 port_op;
};

struct pf_rule {
	struct pf_rule_addr	 src;
	struct pf_rule_addr	 dst;

	u_int64_t		 evaluations;
	u_int64_t		 packets[2];
	u_int64_t		 bytes[2];

	u_int32_t	 	 rule_flag;
  	u_int8_t		 action;
 	u_int8_t		 direction;
	u_int8_t		 log;
	u_int8_t		 logif;
	u_int8_t		 quick;

	u_int8_t		 proto;

#define PF_STATE_NORMAL		0x1
#define PF_STATE_MODULATE	0x2
#define PF_STATE_SYNPROXY	0x3
	u_int8_t		 keep_state;
	sa_family_t		 af;
};

struct pfioc_rule {
	u_int32_t	 action;
	u_int32_t	 ticket;
	u_int32_t	 pool_ticket;
	u_int32_t	 nr;
	char		 anchor[MAXPATHLEN];
	char		 anchor_call[MAXPATHLEN];
	struct pf_rule	 rule;
};

enum	{ PF_INOUT, PF_IN, PF_OUT };
enum	{ PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
	  PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP, PF_DEFER,
	  PF_MATCH };
enum	{ PF_OP_NONE, PF_OP_IRG, PF_OP_EQ, PF_OP_NE, PF_OP_LT,
	  PF_OP_LE, PF_OP_GT, PF_OP_GE, PF_OP_XRG, PF_OP_RRG };

/* rule flags */
#define	PFRULE_DROP			0x0000
#define	PFRULE_RETURNRST	0x0001
#define	PFRULE_FRAGMENT		0x0002
#define	PFRULE_RETURNICMP	0x0004
#define	PFRULE_RETURN		0x0008
#define	PFRULE_NOSYNC		0x0010
#define PFRULE_SRCTRACK		0x0020  /* track source states */
#define PFRULE_RULESRCTRACK	0x0040  /* per rule */

#endif /* _PFVAR_H_ */