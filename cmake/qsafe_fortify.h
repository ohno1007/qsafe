#pragma once

// Bionic's fortified calls use the sizes of objects known at compile time.
// Preserve a higher level supplied by the consuming project.
#if defined(__OPTIMIZE__) && (!defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE < 2)
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#endif
