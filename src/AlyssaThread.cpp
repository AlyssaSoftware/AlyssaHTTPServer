#include "Alyssa.h"
#include "PollenTemporary.h"

void AlyssaThread(int num) {
	char* buf = thrArray[num].buf;
#define cl clArray[thrArray[num].shared[0]]
#define type thrArray[num].shared[1]
	while (true) {
		// Wait for a new client
		while (!thrArray[num].lk) Sleep(50);
		// Handle the new client
		switch (type) {
			case 1: 
				switch (switch_on) {
				default:
					break;
				}
			default: break;
		}
	}
}