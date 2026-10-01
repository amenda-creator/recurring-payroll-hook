/**
 * Recurring Payroll Hook (Xahau)
 *
 * Pays a fixed amount of XAH to each of 5 employee accounts once every
 * interval (default: 200 XAH every 1,209,600 s = 2 weeks), forever.
 *
 * Configuration - Hook Parameters set at install time (SetHook):
 *   E0..E4 : 20-byte AccountID of each employee           (REQUIRED)
 *   AMT    : 8-byte big-endian uint64, drops per employee  (optional, default 200 XAH)
 *   INT    : 8-byte big-endian uint64, seconds between payouts (optional, default 1209600)
 *
 * Triggers (any of these runs the "is payroll due?" check):
 *   - Cron    : scheduled callback (configure with a CronSet on the hook account)
 *   - Invoke  : manual / bot "ping" from anyone
 *   - Payment : any INCOMING payment to the hook account (e.g. a top-up)
 *
 * State:
 *   key "LASTPAY" -> 8-byte big-endian ledger close time (Ripple epoch seconds)
 *                    of the last successful payout.
 *
 * If no payout has ever happened, the first trigger pays immediately.
 * Payouts are only emitted if the account balance covers all 5 payments plus
 * a safety buffer; otherwise the trigger is accepted and the payout deferred.
 */
#include "hookapi.h"

#define EMPLOYEE_COUNT         5
#define DEFAULT_AMOUNT_DROPS   200000000ULL        /* 200 XAH            */
#define DEFAULT_INTERVAL_SECS  1209600ULL          /* 14 days            */
#define MAX_AMOUNT_DROPS       1000000000000ULL    /* 1,000,000 XAH cap  */
#define MIN_INTERVAL_SECS      60ULL
#define RESERVE_BUFFER_DROPS   10000000ULL         /* keep 10 XAH spare for reserve + fees */

/* ---- byte helpers (big-endian) ---- */
#define PR_U64_FROM_BE(b) ( \
    ((uint64_t)(b)[0] << 56) | ((uint64_t)(b)[1] << 48) | \
    ((uint64_t)(b)[2] << 40) | ((uint64_t)(b)[3] << 32) | \
    ((uint64_t)(b)[4] << 24) | ((uint64_t)(b)[5] << 16) | \
    ((uint64_t)(b)[6] <<  8) |  (uint64_t)(b)[7])

#define PR_U64_TO_BE(b, v) { \
    uint64_t __v = (uint64_t)(v); \
    (b)[0] = (uint8_t)(__v >> 56); (b)[1] = (uint8_t)(__v >> 48); \
    (b)[2] = (uint8_t)(__v >> 40); (b)[3] = (uint8_t)(__v >> 32); \
    (b)[4] = (uint8_t)(__v >> 24); (b)[5] = (uint8_t)(__v >> 16); \
    (b)[6] = (uint8_t)(__v >>  8); (b)[7] = (uint8_t)(__v); }

#define PR_U32_TO_BE(b, v) { \
    uint32_t __w = (uint32_t)(v); \
    (b)[0] = (uint8_t)(__w >> 24); (b)[1] = (uint8_t)(__w >> 16); \
    (b)[2] = (uint8_t)(__w >>  8); (b)[3] = (uint8_t)(__w); }

/* Native XAH amount: bit63=0 (native), bit62=1 (positive), 62-bit drops */
#define ENCODE_DROPS_AT(b, drops) { \
    uint64_t __d = (uint64_t)(drops); \
    (b)[0] = (uint8_t)(0x40U | ((__d >> 56) & 0x3FU)); \
    (b)[1] = (uint8_t)(__d >> 48); (b)[2] = (uint8_t)(__d >> 40); \
    (b)[3] = (uint8_t)(__d >> 32); (b)[4] = (uint8_t)(__d >> 24); \
    (b)[5] = (uint8_t)(__d >> 16); (b)[6] = (uint8_t)(__d >>  8); \
    (b)[7] = (uint8_t)(__d); }

#define DECODE_NATIVE_DROPS(b) ( \
    (((uint64_t)(b)[0] & 0x3FULL) << 56) | ((uint64_t)(b)[1] << 48) | \
    ((uint64_t)(b)[2] << 40) | ((uint64_t)(b)[3] << 32) | \
    ((uint64_t)(b)[4] << 24) | ((uint64_t)(b)[5] << 16) | \
    ((uint64_t)(b)[6] <<  8) |  (uint64_t)(b)[7])

/* ---- serialized native-XAH Payment template, patched in place ---- */
#define OFF_FLS           15   /* FirstLedgerSequence value (4) */
#define OFF_LLS           21   /* LastLedgerSequence value  (4) */
#define OFF_AMOUNT        26   /* Amount (8)                    */
#define OFF_FEE           35   /* Fee (8)                       */
#define OFF_ACCOUNT       80   /* Account (20)                  */
#define OFF_DEST         102   /* Destination (20)              */
#define OFF_EMIT_DETAILS 122   /* EmitDetails written by etxn_details() */
#define TXN_MAX          300

static uint8_t txn[TXN_MAX] = {
/*   0 */ 0x12U, 0x00U, 0x00U,                          /* TransactionType = Payment     */
/*   3 */ 0x22U, 0x80U, 0x00U, 0x00U, 0x00U,            /* Flags = tfCanonical           */
/*   8 */ 0x24U, 0x00U, 0x00U, 0x00U, 0x00U,            /* Sequence = 0 (emitted)        */
/*  13 */ 0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,     /* FirstLedgerSequence           */
/*  19 */ 0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,     /* LastLedgerSequence            */
/*  25 */ 0x61U, 0,0,0,0,0,0,0,0,                       /* Amount                        */
/*  34 */ 0x68U, 0,0,0,0,0,0,0,0,                       /* Fee                           */
/*  43 */ 0x73U, 0x21U,                                 /* SigningPubKey (33 x 0x00)     */
          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/*  78 */ 0x81U, 0x14U,                                 /* Account                       */
          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 100 */ 0x83U, 0x14U,                                 /* Destination                   */
          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
/* 122 */ /* EmitDetails appended at runtime */
};

static uint8_t state_key[8] = "LASTPAY";

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    uint8_t hook_accid[20];
    if (hook_account(SBUF(hook_accid)) != 20)
        rollback(SBUF("payroll: could not read hook account"), __LINE__);

    /* ---- 1. Ignore our own outgoing / emitted payments ---- */
    int64_t tt = otxn_type();
    if (tt == ttPAYMENT)
    {
        uint8_t dest[20];
        if (otxn_field(SBUF(dest), sfDestination) != 20)
            accept(SBUF("payroll: payment without destination, ignored"), __LINE__);

        int is_incoming = 0;
        BUFFER_EQUAL(is_incoming, hook_accid, dest, 20);
        if (!is_incoming)
            accept(SBUF("payroll: outgoing/emitted payment, ignored"), __LINE__);
    }
    /* Invoke and Cron fall through: both act as a "check payroll" ping. */

    /* ---- 2. Load configuration ---- */
    uint8_t pbuf[8];
    uint8_t key_amt[3] = { 'A', 'M', 'T' };
    uint8_t key_int[3] = { 'I', 'N', 'T' };

    uint64_t amount = DEFAULT_AMOUNT_DROPS;
    int64_t plen = hook_param(SBUF(pbuf), (uint32_t)key_amt, 3);
    if (plen == 8)
        amount = PR_U64_FROM_BE(pbuf);
    else if (plen >= 0)
        rollback(SBUF("payroll: AMT param must be 8 bytes (uint64 drops)"), __LINE__);

    if (amount == 0 || amount > MAX_AMOUNT_DROPS)
        rollback(SBUF("payroll: AMT out of range"), __LINE__);

    uint64_t interval = DEFAULT_INTERVAL_SECS;
    plen = hook_param(SBUF(pbuf), (uint32_t)key_int, 3);
    if (plen == 8)
        interval = PR_U64_FROM_BE(pbuf);
    else if (plen >= 0)
        rollback(SBUF("payroll: INT param must be 8 bytes (uint64 seconds)"), __LINE__);

    if (interval < MIN_INTERVAL_SECS)
        rollback(SBUF("payroll: INT too small"), __LINE__);

    /* ---- 3. Is a payout due? ---- */
    int64_t now = ledger_last_time();
    if (now <= 0)
        rollback(SBUF("payroll: could not read ledger time"), __LINE__);

    uint8_t last_buf[8];
    int64_t last_len = state(SBUF(last_buf), SBUF(state_key));
    if (last_len == 8)
    {
        int64_t last = (int64_t)PR_U64_FROM_BE(last_buf);
        if (now < last || (uint64_t)(now - last) < interval)
            accept(SBUF("payroll: not due yet"), __LINE__);
    }
    /* no state yet => never paid => due now */

    /* ---- 4. Validate all employee accounts BEFORE emitting anything ---- */
    uint8_t acc_tmp[20];
    uint8_t pname[2] = { 'E', '0' };
    for (int i = 0; GUARD(EMPLOYEE_COUNT), i < EMPLOYEE_COUNT; ++i)
    {
        pname[1] = (uint8_t)('0' + i);
        if (hook_param(SBUF(acc_tmp), (uint32_t)pname, 2) != 20)
            rollback(SBUF("payroll: employee param E0..E4 missing or not 20 bytes"), __LINE__);
    }

    /* ---- 5. Balance check (defer payout instead of emitting unfunded txns) ---- */
    uint8_t kl[34];
    if (util_keylet(SBUF(kl), KEYLET_ACCOUNT, (uint32_t)hook_accid, 20, 0, 0, 0, 0) != 34)
        rollback(SBUF("payroll: keylet failed"), __LINE__);

    int64_t acc_slot = slot_set(SBUF(kl), 0);
    if (acc_slot < 0)
        rollback(SBUF("payroll: could not slot account root"), __LINE__);

    int64_t bal_slot = slot_subfield(acc_slot, sfBalance, 0);
    if (bal_slot < 0)
        rollback(SBUF("payroll: could not slot balance"), __LINE__);

    uint8_t bal_buf[8];
    if (slot(SBUF(bal_buf), bal_slot) != 8 || (bal_buf[0] & 0x80U))
        rollback(SBUF("payroll: unexpected balance format"), __LINE__);

    uint64_t balance = DECODE_NATIVE_DROPS(bal_buf);
    uint64_t required = amount * EMPLOYEE_COUNT + RESERVE_BUFFER_DROPS;
    if (balance < required)
        accept(SBUF("payroll: insufficient balance, payout deferred"), __LINE__);

    /* ---- 6. Emit 5 payments ---- */
    if (etxn_reserve(EMPLOYEE_COUNT) != EMPLOYEE_COUNT)
        rollback(SBUF("payroll: etxn_reserve failed"), __LINE__);

    if (hook_account((uint32_t)(txn + OFF_ACCOUNT), 20) != 20)
        rollback(SBUF("payroll: could not write source account"), __LINE__);

    ENCODE_DROPS_AT(txn + OFF_AMOUNT, amount);

    uint32_t cls = (uint32_t)ledger_seq();
    PR_U32_TO_BE(txn + OFF_FLS, cls + 1);
    PR_U32_TO_BE(txn + OFF_LLS, cls + 5);

    for (int i = 0; GUARD(EMPLOYEE_COUNT), i < EMPLOYEE_COUNT; ++i)
    {
        pname[1] = (uint8_t)('0' + i);
        if (hook_param((uint32_t)(txn + OFF_DEST), 20, (uint32_t)pname, 2) != 20)
            rollback(SBUF("payroll: could not read employee account"), __LINE__);

        int64_t ed_len = etxn_details((uint32_t)(txn + OFF_EMIT_DETAILS), TXN_MAX - OFF_EMIT_DETAILS);
        if (ed_len <= 0)
            rollback(SBUF("payroll: etxn_details failed"), __LINE__);

        uint32_t txn_len = OFF_EMIT_DETAILS + (uint32_t)ed_len;

        int64_t fee = etxn_fee_base((uint32_t)txn, txn_len);
        if (fee < 0)
            rollback(SBUF("payroll: fee calculation failed"), __LINE__);
        ENCODE_DROPS_AT(txn + OFF_FEE, fee);

        uint8_t emithash[32];
        if (emit(SBUF(emithash), (uint32_t)txn, txn_len) != 32)
            rollback(SBUF("payroll: emit failed"), __LINE__);
    }

    /* ---- 7. Record payout time (no end condition: repeats every interval) ---- */
    uint8_t now_buf[8];
    PR_U64_TO_BE(now_buf, (uint64_t)now);
    if (state_set(SBUF(now_buf), SBUF(state_key)) != 8)
        rollback(SBUF("payroll: could not update last-payment state"), __LINE__);

    accept(SBUF("payroll: 5 employee payments emitted"), __LINE__);
    _g(1, 1);
    return 0;
}
