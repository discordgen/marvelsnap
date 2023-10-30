import time
import sys
import traceback
from hecc import gen_task, incr_counter
from colorama import Fore,init
from os import system
from concurrent.futures import ThreadPoolExecutor



worker_count = 250
genned = 0
fail = 0
def print_statusline():
  while True:
    system('cls')
    
    print(Fore.GREEN + """
**********************************************  
*                                            *
*         Marvel snap promos gen             *  
*                                            *
* """ + Fore.YELLOW + f"              Generated: {str(genned)}                 " + Fore.GREEN + """*  
*                                            *
**********************************************
""", end='\r')

    sys.stdout.flush()
    time.sleep(1)

def genr():
    global genned , fail
    while True:
        start = time.time()
        try:
            gen_task()
            genned += 1
            incr_counter("promo_success", time.time() - start)
        except:
            traceback.print_exc()
            fail += 1
            incr_counter("promo_failed", time.time() - start)
            continue

if __name__ == "__main__":
    init(autoreset=True)
    with ThreadPoolExecutor(max_workers=None) as executor:
        executor.submit(print_statusline)
        for _ in range(worker_count):executor.submit(genr)