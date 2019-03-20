package sspcrypto

import "math/rand"

const (
	MAX_PRIME_NUMBER = int64(2147483648)
	MAX_RANDOM_INTEGER = int64(2147483648)
)

func GeneratePrime() uint64 {
	var tmp uint64 = 0;

	tmp	= rand.Uint64();
	tmp	%= uint64(MAX_PRIME_NUMBER);

	/*  ensure it is an odd number	*/
	if (tmp & 1)==0 {
		tmp += 1;
	}
	/*  increment until prime  */
	for !MillerRabin(int64(tmp), 5) {
		tmp +=2
	}
	return tmp
}

/*	MillerRabin Performs the miller-rabin primality test on a guessed prime n.
|	trials is the number of attempts to verify this, because the function
|	is not 100% accurate it may be a composite.  However setting the trial
|	value to around 5 should guarantee success even with very large primes		*/
func MillerRabin (n int64, trials int64) bool {
	var a int64 = 0
	var i int64

	for i=0; i<trials; i++ {
		a = (rand.Int63() % (n-3))+2;/* gets random value in [2..n-1] */

		if !IsItPrime(n,a) {
			return false;
			/*n composite, return false */
		}
	}
	return true; /* n probably prime */
}

// IsItPrime Checks the integer n for primality
func IsItPrime (n int64, a int64) bool {
	d := XpowYmodN(a, n-1, n);
	return d==1
}

/*
	XpowYmodN Raises X to the power Y in modulus N
	the values of X, Y, and N can be massive, and this can be
	achieved by first calculating X to the power of 2 then
	using power chaining over modulus N
*/
func XpowYmodN(x int64, y int64, N int64) int64 {
	var i int
	var result int64 = 1
	var oneShift63 = result << 63
	if y==1 {
		return x % N
	}
	for i = 0; i < 64; {
		result = result * result % N;
		if y & oneShift63 != 0 {
			result = result * x % N;
		}
		y = y << 1
		i++
	}
	return result
}

