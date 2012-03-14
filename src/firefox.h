/**
*******************************************************************************
*                                   4IF                       
*                   (c) Copyright 2011, INSA de Lyon, FR
*                      
*                          All Rights Reserved
*
* \brief            TODO. 
* \author           Rodrigo CASTRO.
*******************************************************************************
*/

/*
*******************************************************************************
*                                  Defines
*******************************************************************************
*/

#ifndef FIREFOX_H
#define FIREFOX_H

#include <Windows.h>

// TODO use real headers !
// see https://developer.mozilla.org/en/PRFileDesc
typedef int PRInt32;
typedef DWORD PRIOMethods;
typedef DWORD PRFilePrivate;

typedef unsigned int PRUintn;
typedef PRUintn PRDescIdentity;

struct PRFileDesc {
  PRIOMethods *methods;
  PRFilePrivate *secret;
  PRFileDesc *lower, *higher;
  void (*dtor)(PRFileDesc *fd);
  PRDescIdentity identity;
};

typedef struct PRFileDesc PRFileDesc;

typedef PRInt32		 ( * FUNC_PR_Write)  ( PRFileDesc * fd, const void * buf, PRInt32 amount);


#endif // CONFIG_H