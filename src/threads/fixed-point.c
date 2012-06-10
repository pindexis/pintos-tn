
#include "threads/fixed-point.h"
#include <limits.h>
#include <stdio.h>
#define q 16384 //2^14
#define p 131072 //2^17
int _casttoint(int64_t x);

int converttofixed(int n)
{
	if(n<p && n>=(-p))
	return n*q;
	else
	{
	printf("converttofixed Overflow\n");
	return 0;
	}
}
int frounddown(int x)
{
	return x/q;
}
int fround(int x)
{
return (x>=0)?((x+q/2)/q):((x-q/2)/q);
}
int fadd(int x,int y)
{
	if((x>0 &&  INT_MAX-x<y) || (x<0 && INT_MIN-x>y))
	{
	printf("fadd overflow\n");
	return 0;
	}
	return x+y;
}
int faddm(int x,int n)
{
	return fadd(x,converttofixed(n));
}
int fsubb(int x,int y)
{
	if(y!=INT_MIN)
	return fadd(x,-y);
	else if(x<0)
	return fadd(x+1,INT_MAX);
	else
	{
		printf("fusbb overflow\n");
		return 0;
	}
}
int fsubbm(int x,int n)
{
	return fsubb(x,converttofixed(n));
}
int fmultiply(int x,int y)
{
	return _casttoint(((int64_t)x)*y/q);
}
int fmultiplym(int x,int n)
{
	return fmultiply(x,converttofixed(n));
}
int fdivide(int x,int y)
{
	return _casttoint((int64_t)x*q/y);
}
int fdividem(int x,int n)
{
	return fdivide(x,converttofixed(n));
}
int _casttoint(int64_t x)
{
	if((x>>32)!=0 && (x>>32)!=-1)
	{
	printf("_CastToInt overflow \n");
	}
	 return (int)(x-((x>>32)<<32));
}
