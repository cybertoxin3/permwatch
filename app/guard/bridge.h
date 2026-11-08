// permwatch-guard C köprüsü: Endpoint Security (çalıştırma izni), libbsm (denetim belirteci) ve libyara.
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <yara.h>
