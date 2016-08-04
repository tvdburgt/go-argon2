// Wrapper function to pass pointers as individual parameters.
//
// Go does not allow passing memory containing Go pointers as this
// would fail when the garbage collector moves things around. Passing
// pointers as parameters to a single C call is allowed, so the struct
// must be instantiated, used and freed all within a single C
// function.
int argon2_wrapper(uint8_t *out, uint32_t outlen,
		   uint8_t *pwd, uint32_t pwdlen,
		   uint8_t *salt, uint32_t saltlen,
		   uint8_t *secret, uint32_t secretlen,
		   uint8_t *ad, uint32_t adlen,

		   uint32_t t_cost,
		   uint32_t m_cost,
		   uint32_t lanes,
		   uint32_t threads,

		   uint32_t version,

		   allocate_fptr allocate_cbk,
		   deallocate_fptr free_cbk,

		   uint32_t flags,
		   argon2_type type) {

	argon2_context context = {
		.out = out,
		.outlen = outlen,

		.pwd = pwd,
		.pwdlen = pwdlen,

		.salt = salt,
		.saltlen = saltlen,

		.secret = secret,
		.secretlen = secretlen,

		.ad = ad,
		.adlen = adlen,

		.t_cost = t_cost,
		.m_cost = m_cost,
		.lanes = lanes,
		.threads = threads,

		.version = version,

		.allocate_cbk = allocate_cbk,
		.free_cbk = free_cbk,

		.flags = flags
	};

	return argon2_ctx(&context, type);
}
