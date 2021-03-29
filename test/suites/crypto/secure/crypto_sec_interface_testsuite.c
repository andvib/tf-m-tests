/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "test_framework_helpers.h"
#include "tfm_secure_client_2_api.h"
#include "tfm_api.h"
#include "../crypto_tests_common.h"

/* List of tests */
static void tfm_crypto_test_2001(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_CBC
static void tfm_crypto_test_2002(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CBC */
#ifdef TFM_CRYPTO_TEST_ALG_CFB
static void tfm_crypto_test_2003(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CFB */
#ifdef TFM_CRYPTO_TEST_ALG_CTR
static void tfm_crypto_test_2005(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CTR */
static void tfm_crypto_test_2007(struct test_result_t *ret);
static void tfm_crypto_test_2008(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_CFB
static void tfm_crypto_test_2009(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CFB */
static void tfm_crypto_test_2010(struct test_result_t *ret);
static void tfm_crypto_test_2011(struct test_result_t *ret);
static void tfm_crypto_test_2012(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
static void tfm_crypto_test_2013(struct test_result_t *ret);
static void tfm_crypto_test_2014(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */
static void tfm_crypto_test_2019(struct test_result_t *ret);
static void tfm_crypto_test_2020(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
static void tfm_crypto_test_2021(struct test_result_t *ret);
static void tfm_crypto_test_2022(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */
static void tfm_crypto_test_2024(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_CCM
static void tfm_crypto_test_2030(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CCM */
#ifdef TFM_CRYPTO_TEST_ALG_GCM
static void tfm_crypto_test_2031(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_GCM */
static void tfm_crypto_test_2032(struct test_result_t *ret);
static void tfm_crypto_test_2033(struct test_result_t *ret);
static void tfm_crypto_test_2034(struct test_result_t *ret);
static void tfm_crypto_test_2035(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_ALG_CCM
static void tfm_crypto_test_2036(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_ALG_CCM */
static void tfm_crypto_test_2037(struct test_result_t *ret);
static void tfm_crypto_test_2038(struct test_result_t *ret);
#ifdef TFM_CRYPTO_TEST_HKDF
static void tfm_crypto_test_2039(struct test_result_t *ret);
#endif /* TFM_CRYPTO_TEST_HKDF */

static struct test_t crypto_tests[] = {
    {&tfm_crypto_test_2001, "TFM_CRYPTO_TEST_2001",
     "Secure Key management interface", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_CBC
    {&tfm_crypto_test_2002, "TFM_CRYPTO_TEST_2002",
     "Secure Symmetric encryption (AES-128-CBC) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CBC */
#ifdef TFM_CRYPTO_TEST_ALG_CFB
    {&tfm_crypto_test_2003, "TFM_CRYPTO_TEST_2003",
     "Secure Symmetric encryption (AES-128-CFB) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CFB */
#ifdef TFM_CRYPTO_TEST_ALG_CTR
    {&tfm_crypto_test_2005, "TFM_CRYPTO_TEST_2005",
     "Secure Symmetric encryption (AES-128-CTR) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CTR */
    {&tfm_crypto_test_2007, "TFM_CRYPTO_TEST_2007",
     "Secure Symmetric encryption invalid cipher", {TEST_PASSED} },
    {&tfm_crypto_test_2008, "TFM_CRYPTO_TEST_2008",
     "Secure Symmetric encryption invalid cipher (AES-152)", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_CFB
    {&tfm_crypto_test_2009, "TFM_CRYPTO_TEST_2009",
     "Secure Symmetric encryption invalid cipher (HMAC-128-CFB)", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CFB */
    {&tfm_crypto_test_2010, "TFM_CRYPTO_TEST_2010",
     "Secure Unsupported Hash (SHA-1) interface", {TEST_PASSED} },
    {&tfm_crypto_test_2011, "TFM_CRYPTO_TEST_2011",
     "Secure Hash (SHA-224) interface", {TEST_PASSED} },
    {&tfm_crypto_test_2012, "TFM_CRYPTO_TEST_2012",
     "Secure Hash (SHA-256) interface", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
    {&tfm_crypto_test_2013, "TFM_CRYPTO_TEST_2013",
     "Secure Hash (SHA-384) interface", {TEST_PASSED} },
    {&tfm_crypto_test_2014, "TFM_CRYPTO_TEST_2014",
     "Secure Hash (SHA-512) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */
    {&tfm_crypto_test_2019, "TFM_CRYPTO_TEST_2019",
     "Secure Unsupported HMAC (SHA-1) interface", {TEST_PASSED} },
    {&tfm_crypto_test_2020, "TFM_CRYPTO_TEST_2020",
     "Secure HMAC (SHA-256) interface", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
    {&tfm_crypto_test_2021, "TFM_CRYPTO_TEST_2021",
     "Secure HMAC (SHA-384) interface", {TEST_PASSED} },
    {&tfm_crypto_test_2022, "TFM_CRYPTO_TEST_2022",
     "Secure HMAC (SHA-512) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */
    {&tfm_crypto_test_2024, "TFM_CRYPTO_TEST_2024",
     "Secure HMAC with long key (SHA-224) interface", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_CCM
    {&tfm_crypto_test_2030, "TFM_CRYPTO_TEST_2030",
     "Secure AEAD (AES-128-CCM) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CCM */
#ifdef TFM_CRYPTO_TEST_ALG_GCM
    {&tfm_crypto_test_2031, "TFM_CRYPTO_TEST_2031",
     "Secure AEAD (AES-128-GCM) interface", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_GCM */
    {&tfm_crypto_test_2032, "TFM_CRYPTO_TEST_2032",
     "Secure key policy interface", {TEST_PASSED} },
    {&tfm_crypto_test_2033, "TFM_CRYPTO_TEST_2033",
     "Secure key policy check permissions", {TEST_PASSED} },
    {&tfm_crypto_test_2034, "TFM_CRYPTO_TEST_2034",
     "Secure persistent key interface", {TEST_PASSED} },
    {&tfm_crypto_test_2035, "TFM_CRYPTO_TEST_2035",
     "Key access control", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_ALG_CCM
    {&tfm_crypto_test_2036, "TFM_CRYPTO_TEST_2036",
     "Secure AEAD interface with truncated auth tag (AES-128-CCM-8)",
     {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_ALG_CCM */
    {&tfm_crypto_test_2037, "TFM_CRYPTO_TEST_2037",
     "Secure TLS 1.2 PRF key derivation", {TEST_PASSED} },
    {&tfm_crypto_test_2038, "TFM_CRYPTO_TEST_2038",
     "Secure TLS-1.2 PSK-to-MasterSecret key derivation", {TEST_PASSED} },
#ifdef TFM_CRYPTO_TEST_HKDF
    {&tfm_crypto_test_2039, "TFM_CRYPTO_TEST_2039",
     "Secure HKDF key derivation", {TEST_PASSED} },
#endif /* TFM_CRYPTO_TEST_HKDF */
};

void register_testsuite_s_crypto_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size = (sizeof(crypto_tests) / sizeof(crypto_tests[0]));

    set_testsuite("Crypto secure interface tests (TFM_CRYPTO_TEST_2XXX)",
                  crypto_tests, list_size, p_test_suite);
}

/**
 * \brief Secure interface test for Crypto
 *
 * \details The scope of this set of tests is to functionally verify
 *          the interfaces specified by psa/crypto.h are working
 *          as expected. This is not meant to cover all possible
 *          scenarios and corner cases.
 *
 */
static void tfm_crypto_test_2001(struct test_result_t *ret)
{
    psa_key_interface_test(PSA_KEY_TYPE_AES, ret);
}

#ifdef TFM_CRYPTO_TEST_ALG_CBC
static void tfm_crypto_test_2002(struct test_result_t *ret)
{
    psa_cipher_test(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_CBC */

#ifdef TFM_CRYPTO_TEST_ALG_CFB
static void tfm_crypto_test_2003(struct test_result_t *ret)
{
    psa_cipher_test(PSA_KEY_TYPE_AES, PSA_ALG_CFB, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_CFB */

#ifdef TFM_CRYPTO_TEST_ALG_CTR
static void tfm_crypto_test_2005(struct test_result_t *ret)
{
    psa_cipher_test(PSA_KEY_TYPE_AES, PSA_ALG_CTR, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_CTR */

static void tfm_crypto_test_2007(struct test_result_t *ret)
{
    psa_invalid_cipher_test(PSA_KEY_TYPE_AES, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                            16, ret);
}

static void tfm_crypto_test_2008(struct test_result_t *ret)
{
    psa_invalid_key_length_test(ret);
}

#ifdef TFM_CRYPTO_TEST_ALG_CFB
static void tfm_crypto_test_2009(struct test_result_t *ret)
{
    /* HMAC is not a block cipher */
    psa_invalid_cipher_test(PSA_KEY_TYPE_HMAC, PSA_ALG_CFB, 16, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_CFB */

static void tfm_crypto_test_2010(struct test_result_t *ret)
{
    psa_unsupported_hash_test(PSA_ALG_SHA_1, ret);
}

static void tfm_crypto_test_2011(struct test_result_t *ret)
{
    psa_hash_test(PSA_ALG_SHA_224, ret);
}

static void tfm_crypto_test_2012(struct test_result_t *ret)
{
    psa_hash_test(PSA_ALG_SHA_256, ret);
}

#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
static void tfm_crypto_test_2013(struct test_result_t *ret)
{
    psa_hash_test(PSA_ALG_SHA_384, ret);
}

static void tfm_crypto_test_2014(struct test_result_t *ret)
{
    psa_hash_test(PSA_ALG_SHA_512, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */

static void tfm_crypto_test_2019(struct test_result_t *ret)
{
    psa_unsupported_mac_test(PSA_KEY_TYPE_HMAC, PSA_ALG_HMAC(PSA_ALG_SHA_1),
                             ret);
}

static void tfm_crypto_test_2020(struct test_result_t *ret)
{
    psa_mac_test(PSA_ALG_HMAC(PSA_ALG_SHA_256), 0, ret);
}

#ifdef TFM_CRYPTO_TEST_ALG_SHA_512
static void tfm_crypto_test_2021(struct test_result_t *ret)
{
    psa_mac_test(PSA_ALG_HMAC(PSA_ALG_SHA_384), 0, ret);
}

static void tfm_crypto_test_2022(struct test_result_t *ret)
{
    psa_mac_test(PSA_ALG_HMAC(PSA_ALG_SHA_512), 0, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_SHA_512 */

static void tfm_crypto_test_2024(struct test_result_t *ret)
{
    psa_mac_test(PSA_ALG_HMAC(PSA_ALG_SHA_224), 1, ret);
}

#ifdef TFM_CRYPTO_TEST_ALG_CCM
static void tfm_crypto_test_2030(struct test_result_t *ret)
{
    psa_aead_test(PSA_KEY_TYPE_AES, PSA_ALG_CCM, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_CCM */

#ifdef TFM_CRYPTO_TEST_ALG_GCM
static void tfm_crypto_test_2031(struct test_result_t *ret)
{
    psa_aead_test(PSA_KEY_TYPE_AES, PSA_ALG_GCM, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_GCM */

static void tfm_crypto_test_2032(struct test_result_t *ret)
{
    psa_policy_key_interface_test(ret);
}

static void tfm_crypto_test_2033(struct test_result_t *ret)
{
    psa_policy_invalid_policy_usage_test(ret);
}

static void tfm_crypto_test_2034(struct test_result_t *ret)
{
    psa_persistent_key_test(1, ret);
}

/**
 * \brief Tests key access control based on partition ID
 *
 * \param[out] ret  Test result
 */
static void tfm_crypto_test_2035(struct test_result_t *ret)
{
    psa_status_t status;
    psa_key_handle_t key_handle;
    const uint8_t data[] = "THIS IS MY KEY1";
    psa_key_attributes_t key_attributes = psa_key_attributes_init();

    /* Set key sage and type */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);

    status = psa_import_key(&key_attributes, data, sizeof(data),
                            &key_handle);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Failed to import key");
        return;
    }

    /* Attempt to destroy the key handle from the Secure Client 2 partition */
    status = tfm_secure_client_2_call_test(
                                      TFM_SECURE_CLIENT_2_ID_CRYPTO_ACCESS_CTRL,
                                      &key_handle, sizeof(key_handle));
    if (status != PSA_ERROR_NOT_PERMITTED) {
        TEST_FAIL("Should not be able to destroy key from another partition");
        return;
    }

    /* Destroy the key */
    status = psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Error destroying a key");
    }
    return;
}

#ifdef TFM_CRYPTO_TEST_ALG_CCM
static void tfm_crypto_test_2036(struct test_result_t *ret)
{
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_TAG_LENGTH(PSA_ALG_CCM,
                                                       TRUNCATED_AUTH_TAG_LEN);

    psa_aead_test(PSA_KEY_TYPE_AES, alg, ret);
}
#endif /* TFM_CRYPTO_TEST_ALG_GCM */

static void tfm_crypto_test_2037(struct test_result_t *ret)
{
    psa_key_derivation_test(PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256), ret);
}

static void tfm_crypto_test_2038(struct test_result_t *ret)
{
    psa_key_derivation_test(PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256), ret);
}

#ifdef TFM_CRYPTO_TEST_HKDF
static void tfm_crypto_test_2039(struct test_result_t *ret)
{
    psa_key_derivation_test(PSA_ALG_HKDF(PSA_ALG_SHA_256), ret);
}
#endif /* TFM_CRYPTO_TEST_HKDF */
