# Python3 code to test whether the
# mobile's IMEI number is valid or not.
# Uses  Luhn algorithm


def sumDig(n):
    a = 0
    while n > 0:
        a = a + n % 10
        n = int(n / 10)

    return a


# Returns True if IMEI_str is a valid IMEI
def isValidIMEI(IMEI_str):

    length = len(IMEI_str)

    # If length is not 15,IMEI is Invalid
    if length != 15:
        return False

    d = 0
    IMEI_int = int(IMEI_str)
    sum = 0
    for i in range(15, 0, -1):
        d = (int)(IMEI_int % 10)
        if i % 2 == 0:
            # Doubling every alternate digit
            d = 2 * d
        # Finding sum of the digits
        sum = sum + sumDig(d)
        IMEI_int = IMEI_int / 10
    return (sum % 10 == 0)
