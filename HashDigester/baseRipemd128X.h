//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.6.0.0.1
//
// Copyright © 2009-2012 DiceLock Security, LLC. All rights reserved.
//
//                               DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// DICELOCK IS A REGISTERED TRADEMARK OR TRADEMARK OF THE OWNERS.
// 

#ifndef BASERIPEMD128X_HPP

#define BASERIPEMD128X_HPP

#ifdef DICELOCKCIPHER_EXPORTS
   #define CLASS_DECLSPEC    __declspec(dllexport)
#else
   #define CLASS_DECLSPEC    __declspec(dllimport)
#endif

#include "baseRipemd.h"


#define RIPEMD_Transform128X(f, a, b, c, d, x, s, k)\
	(*a) += f((*b), (*c), (*d)) + x + k;\
	(*a) = RIPEMD_RotateLeft((*a), s);


namespace DiceLockSecurity {

  namespace Hash {

	  class BaseRipemd128X abstract : public BaseRipemd  {

		protected:

			/// First transform set
			CLASS_DECLSPEC void Transform_F0(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Second transform set
			CLASS_DECLSPEC void Transform_G1(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Third transform set
			CLASS_DECLSPEC void Transform_H2(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Fourth transform set
			CLASS_DECLSPEC void Transform_I3(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Fifth transform set
			CLASS_DECLSPEC void Transform_I5(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Sixth transform set
			CLASS_DECLSPEC void Transform_H6(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Seventh transform set
			CLASS_DECLSPEC void Transform_G7(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Eighth transform set
			CLASS_DECLSPEC void Transform_F9(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

		public:

			/// Constructor, default 
			CLASS_DECLSPEC BaseRipemd128X();

			/// Destructor
			CLASS_DECLSPEC ~BaseRipemd128X();
	};
  }
}

#endif