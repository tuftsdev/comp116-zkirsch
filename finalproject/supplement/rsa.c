/*****************************************************************************
 *                               RSA SIMULATOR                               *
 *                                                                           *
 * By:   Zach Kirsch                                                         *
 * Date: 15 Dec 2015                                                         *
 *                                                                           *
 * This RSA Simulator is for introducing how RSA works. There are two modes. *
 *  1. Generate (with option --generate)                                     *
 *     This is for generating an RSA public/private key from two seed primes *
 *  2. Crack (with option --crack)                                           *
 *     This is for cracking an RSA public key. For obvious reasons, this     *
 *     is only functional for small keys.                                    *
 ****************************************************************************/

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GENERATE_OPT "--generate"
#define CRACK_OPT    "--crack"

/* red and bold */
#define STYLE_SPECIAL         "\033[1m\033[31m"
#define STYLE_NO_SPECIAL      "\033[0m"
#define SCREEN_CLEAR          "\e[1;1H\e[2J"

/* function declarations */
void               usage         (char *prgm);
void               generate      ();
void               crack         ();
void               print_intro ();
void               choose_primes (unsigned long long *p, unsigned long long *q);
unsigned long long choose_prime  ();
void               calc_N        (unsigned long long p, unsigned long long q,
                                  unsigned long long *N);
bool               is_prime      (unsigned long long);
void               calc_phi      (unsigned long long N,unsigned long long *phi);
void               choose_e      (unsigned long long phi,unsigned long long *e);
void               calc_d        (unsigned long long e, unsigned long long phi,
                                  unsigned long long *d);
void               get_inputs    (unsigned long long *N, unsigned long long *e);
unsigned long long gcd           (unsigned long long, unsigned long long);
int                min           (int, int);

int main(int argc, char *argv[])
{
        if (argc == 1) usage(argv[0]);
        else if (strncmp(argv[1], GENERATE_OPT, strlen(GENERATE_OPT)) == 0)
                generate();
        else if (strncmp(argv[1], CRACK_OPT, strlen(GENERATE_OPT)) == 0)
                crack();
        else usage(argv[0]);

        return EXIT_SUCCESS;
}

/* prints usage statement when program is called incorrectly */
void usage(char *prgm)
{
        fprintf(stderr, "Usage: %s {%s, %s}\n",
                        prgm,
                        GENERATE_OPT,
                        CRACK_OPT);
        exit(1);
}

/* generates RSA key pair */
void generate()
{
        unsigned long long p, q, N, phi, d, e;

        srand(time(NULL));

        print_intro();

        choose_primes(&p, &q);
        calc_N(p, q, &N);
        calc_phi(N, &phi);
        choose_e(phi, &e);
        calc_d(e, phi, &d);

        fprintf(stdout, "\n"
                        STYLE_SPECIAL
                        "Public Key:  N = %llu & e = %llu\n"
                        "Private Key: d = %llu\n\n"
                        STYLE_NO_SPECIAL, N, e, d);
}

/* cracks RSA public key */
void crack() {
        print_intro();

        unsigned long long N, e, phi, d;
        get_inputs(&N, &e);        
        calc_phi(N, &phi);
        calc_d(e, phi, &d);
}

/* prints the introduction message when the program is run */
void print_intro()
{
        fprintf(stdout, SCREEN_CLEAR);

        char *intro =
        "********************************************************\n"
        "*                      RSA TESTER                      *\n"
        "********************************************************\n"
        "*                                                      *\n"
        "* This is a program for generating test RSA keys for a *\n"
        "* beginner's understanding. RSA keys are produced from *\n"
        "* two primes p and q. In this demo, you will choose p  *\n"
        "* and q. From those two primes, the product N = p * q  *\n"
        "* is calculated, and the Euler totient phi(N) is also  *\n"
        "* calculated. Then, a random e is chosen, and a        *\n"
        "* corresponding d is found such that:                  *\n"
        "*                   e * d = 1 mod phi(N)               *\n"
        "* N and e are the public key, and d is the private     *\n"
        "* key. To encrypt a message M, calculate M^e. To       *\n"
        "* decrypt a message X, calculated X^d, which will      *\n"
        "* result in the original message.                      *\n"
        "*                                                      *\n"
        "* WARNING 1: This is meant for demonstration           *\n"
        "*            purposes only and SHOULD NOT be used to   *\n"
        "*            encrypt any real data.                    *\n"
        "* WARNING 2: This program will overflow on large       *\n"
        "*            numbers, and therefore only small inputs  *\n"
        "*            should be used.                           *\n"
/*
        "* WARNING 3: On certain prime pairs, e and d cannot    *\n"
        "*            be calculated. If the program stalls,     *\n"
        "*            quit via Ctrl+C and try again.            *\n"
*/
        "*                                                      *\n"
        "* Options:                                             *\n"
        "*          --generate: Generate a RSA key pair         *\n"
        "*          --crack:    Try to crack an RSA public key  *\n"
        "********************************************************\n"
        "\n";

        fprintf(stdout, "%s", intro);
}


void choose_primes(unsigned long long *p, unsigned long long *q)
{
        *p = choose_prime();
        *q = choose_prime();
        while (*p == *q) {
                fprintf(stdout, "Primes must be distinct\n");
                *q = choose_prime();
        }
                
        fprintf(stdout, "Primes chosen!\n"
                        STYLE_SPECIAL
                        "p = %llu  q = %llu\n"
                        STYLE_NO_SPECIAL, *p, *q);
}

unsigned long long choose_prime()
{
        unsigned long long p;
        fprintf(stdout, "Enter a prime:  ");
        fscanf(stdin, "%llu", &p);
        while (!is_prime(p)) {
                fprintf(stdout, "That's not a prime! ");
                fprintf(stdout, "Enter a prime:  ");
                fscanf(stdin, "%llu", &p);
        }
        return p;
}

void calc_N(unsigned long long p, unsigned long long q, unsigned long long *N)
{
        *N = p * q;
        fprintf(stdout, "N = p * q = %llu * %llu\n"
                        STYLE_SPECIAL
                        "N = %llu\n"
                        STYLE_NO_SPECIAL, p, q, *N);
}

bool is_prime(unsigned long long p)
{
        if (p < 2) return false;
        for (unsigned long long i = 2; i <= p / 2; i++) {
                if ( p % i == 0 )
                        return false;
        }
        return true;
}

void calc_phi(unsigned long long N, unsigned long long *phi)
{
        *phi = 0;
        for (unsigned long long i = 1; i < N; i++) {
                if ( gcd(N, i) == 1 )
                        (*phi)++;
        }
        fprintf(stdout, "phi(N) is the count of numbers between 1 and N that "
                        "are relatively prime to N.\n"
                        STYLE_SPECIAL
                        "phi(N) = phi(%llu) = %llu\n"
                        STYLE_NO_SPECIAL,
                        N, *phi);
}

/* taken from http://www.math.wustl.edu/~victor/mfmm/compaa/gcd.c */
unsigned long long gcd(unsigned long long a, unsigned long long b)
{
          int c;
          while ( a != 0 ) {
                c = a; a = b%a;  b = c;
          }
          return b;
}

int min(int a, int b)
{
        if (a < b) return a;
        else return b;
}

void choose_e(unsigned long long phi, unsigned long long *e)
{
        do {
                *e = rand() % (phi/2 - 3) + 3;
        } while ( gcd(*e, phi) != 1);
        fprintf(stdout, "e is randomly chosen as part of the public key.\n"
                        STYLE_SPECIAL
                        "e = %llu\n"
                        STYLE_NO_SPECIAL, *e);
}

void calc_d(unsigned long long e, unsigned long long phi, unsigned long long *d)
{
        *d = 3;
        while ( (*d * e) % phi != 1)
                (*d)++;

        fprintf(stdout, "d is calculated such that d * e = 1 mod phi(N). "
                        " %llu * %llu = 1 mod %llu.\n"
                        STYLE_SPECIAL
                        "Private key d is %llu\n"
                        STYLE_NO_SPECIAL, *d, e, phi, *d);
}

/* gets inputs for public key from user for cracking */
void get_inputs(unsigned long long *N, unsigned long long *e)
{
        fprintf(stdout, STYLE_SPECIAL
                        "Enter public key for cracking\n"
                        STYLE_NO_SPECIAL);
        fprintf(stdout, "Enter N from public key:  ");
        fscanf(stdin, "%llu", N);
        while ( is_prime(*N) ) {
                fprintf(stdout, "N cannot be prime\n");
                fprintf(stdout, "Enter N from public key:  ");
                fscanf(stdin, "%llu", N);
        }

        fprintf(stdout, "Enter e from public key:  ");
        fscanf(stdin, "%llu", e);
}
