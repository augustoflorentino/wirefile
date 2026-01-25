#include "wirefile_internal.h"

#define PCW_NSEC_PER_SEC 1000000000u
#define PCW_RESOL_BASE2 0x80u
#define PCW_RESOL_EXP 0x7fu
#define PCW_BASE2_EXACT_BITS 34u

uint64_t pcw_pow10(uint32_t exp)
{
    uint64_t value = 1;

    while (exp-- > 0)
        value *= 10;
    return value;
}

int pcw_ts_resol_valid(uint32_t ts_resol)
{
    if (ts_resol > 0xffu)
        return 0;
    if (ts_resol & PCW_RESOL_BASE2)
        return (ts_resol & PCW_RESOL_EXP) <= 63;
    return ts_resol <= 19;
}

static uint32_t pcw_frac_base2_to_nsec(uint64_t frac, uint32_t exp)
{
    if (exp > PCW_BASE2_EXACT_BITS) {
        frac >>= exp - PCW_BASE2_EXACT_BITS;
        exp = PCW_BASE2_EXACT_BITS;
    }
    return (uint32_t)((frac * PCW_NSEC_PER_SEC) >> exp);
}

static uint32_t pcw_frac_base10_to_nsec(uint64_t frac, uint32_t exp)
{
    if (exp <= 9)
        return (uint32_t)(frac * pcw_pow10(9 - exp));
    return (uint32_t)(frac / pcw_pow10(exp - 9));
}

void pcw_ts_split(uint64_t units, uint32_t ts_resol, int64_t ts_offset, int64_t *out_sec, uint32_t *out_nsec)
{
    uint32_t exp = ts_resol & PCW_RESOL_EXP;
    uint64_t sec;

    if (ts_resol & PCW_RESOL_BASE2) {
        sec = units >> exp;
        *out_nsec = pcw_frac_base2_to_nsec(units - (sec << exp), exp);
    } else {
        sec = units / pcw_pow10(exp);
        *out_nsec = pcw_frac_base10_to_nsec(units % pcw_pow10(exp), exp);
    }
    *out_sec = (int64_t)(sec + (uint64_t)ts_offset);
}

static int pcw_ts_join_base2(uint64_t sec, uint32_t nsec, uint32_t exp, uint64_t *out_units)
{
    uint64_t frac;

    if (exp > 0 && sec >> (64 - exp) != 0)
        return PCW_ERR_ARG;
    if (exp <= PCW_BASE2_EXACT_BITS)
        frac = ((uint64_t)nsec << exp) / PCW_NSEC_PER_SEC;
    else
        frac = (((uint64_t)nsec << PCW_BASE2_EXACT_BITS) / PCW_NSEC_PER_SEC) << (exp - PCW_BASE2_EXACT_BITS);
    *out_units = (sec << exp) | frac;
    return PCW_OK;
}

static int pcw_ts_join_base10(uint64_t sec, uint32_t nsec, uint32_t exp, uint64_t *out_units)
{
    uint64_t scale = pcw_pow10(exp);
    uint64_t frac;

    if (sec > UINT64_MAX / scale)
        return PCW_ERR_ARG;
    frac = exp <= 9 ? nsec / pcw_pow10(9 - exp) : nsec * pcw_pow10(exp - 9);
    if (frac > UINT64_MAX - sec * scale)
        return PCW_ERR_ARG;
    *out_units = sec * scale + frac;
    return PCW_OK;
}

int pcw_ts_join(int64_t sec, uint32_t nsec, uint32_t ts_resol, int64_t ts_offset, uint64_t *out_units)
{
    uint32_t exp = ts_resol & PCW_RESOL_EXP;

    if (nsec >= PCW_NSEC_PER_SEC || !pcw_ts_resol_valid(ts_resol))
        return PCW_ERR_ARG;
    if ((ts_offset > 0 && sec < INT64_MIN + ts_offset) || (ts_offset < 0 && sec > INT64_MAX + ts_offset))
        return PCW_ERR_ARG;
    if (sec - ts_offset < 0)
        return PCW_ERR_ARG;
    if (ts_resol & PCW_RESOL_BASE2)
        return pcw_ts_join_base2((uint64_t)(sec - ts_offset), nsec, exp, out_units);
    return pcw_ts_join_base10((uint64_t)(sec - ts_offset), nsec, exp, out_units);
}
