/* Extracted from libvirt-host.h */
#define VIR_SECURITY_MODEL_BUFLEN 257
#define VIR_SECRUTIY_LABEL_BUFLEN 4097
#define VIR_SECURITY_DOI_BUFLEN 257

/* Extracted from libvirt-common.h.in */

typedef enum {
	VIR_TYPED_PARAM_INT     = 1, /* integer case */
	VIR_TYPED_PARAM_UINT    = 2, /* unsigned integer case */
	VIR_TYPED_PARAM_LLONG   = 3, /* long long case */
	VIR_TYPED_PARAM_ULLONG  = 4, /* unsigned long long case */
	VIR_TYPED_PARAM_DOUBLE  = 5, /* double case */
	VIR_TYPED_PARAM_BOOLEAN = 6, /* boolean(character) case */
	VIR_TYPED_PARAM_STRING  = 7, /* string case */
# ifdef VIR_ENUM_SENTINELS
	VIR_TYPED_PARAM_LAST
# endif
} virTypedParameterType;
