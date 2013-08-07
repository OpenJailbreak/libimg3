AM_CFLAGS = $(libcrypto_CFLAGS) $(libcrippy_CFLAGS) -I$(top_srcdir)/include
AM_LDFLAGS = $(libcrypto_CFLAGS) $(libcrippy_LIBS)

bin_PROGRAMS=img3crypt
img3crypt_SOURCES = img3crypt.c
					
img3crypt_CFLAGS = $(AM_CFLAGS)
img3crypt_LDFLAGS = $(AM_LDFLAGS)
img3crypt_LDADD = $(top_srcdir)/src/libimg3-1.0.la

