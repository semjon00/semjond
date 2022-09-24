# semjond
# A library/framework for automating exploits
# Version: beta9. Kinda stable, report everything you find
"""
# Example semjond module
from semjond import launch

def exploit(teambox_ip, flagid, submit_flag):
    import random
    print(f'Example data: {teambox_ip}, {flagid}')
    submit_flag([f"STUB{random.randint(1000, 9999)}"], True)

if __name__ == '__main__':
    launch("TEST", 15, exploit)
"""

# TODO: HIGH Flag submission immideate feedback
# TODO: HIGH Stats (per tick, per latest 5 ticks)
# TODO: HIGH NOP-team, our-team-staging testing
# TODO: MEDIUM protective data retrieval in semjond threads


from threading import Thread, Lock, Semaphore
from queue import SimpleQueue
from pwnlib import tubes  # Probably this: python3 -m pip install --upgrade pwntools
import time
import requests
import traceback
from datetime import datetime

# COMPETITION-SPECIFIC
JSON_STORAGE = 'http://10.10.254.254/competition/teams.json'
FLAG_SUBMISSION = ('10.10.254.254', 31337)
TEAM_BOX_PATTERN = '10.10.{TEAM_ID}.1'
TEAMID_BLOCKLIST = [8]

print_lock = Lock()
flag_queue_lock = Lock()
flag_queue = SimpleQueue()
connection_semaphore: Semaphore = Semaphore(1)
do_shutdown_flag = False


# Retrieve teams json
def get_json():
    data = {}
    with requests.Session() as s:
        data = s.get(JSON_STORAGE).json()
    return data


def handle_exception(which: str, e: Exception, shutdown: bool = False, additional_info='Nothing here'):
    global do_shutdown_flag
    if shutdown:
        do_shutdown_flag = True
    with print_lock:
        print(f"{which.upper()} THREAD HAS DIED!!!", e)
        traceback.print_exc()
        print(f"\nAdditional info: {additional_info}")


# This thread ensures that flags added trough submit_flag are actually submitted
def flag_submitter_thread():
    got = ''
    global do_shutdown_flag
    try:
        fs = tubes.remote.connect(FLAG_SUBMISSION[0], FLAG_SUBMISSION[1])
        got = fs.recvuntil(b'\n\n')
        last_reconnect = time.time()
        while True:
            with flag_queue_lock:
                while not flag_queue.empty():
                    flag, teambox_ip, flagid, thattime, vocal = flag_queue.get()
                    fs.sendline(flag.encode())
                    got = fs.recvuntil(b'\n')
                    if vocal:
                        with print_lock:
                            print(thattime, teambox_ip, flagid, got, flag)
            if do_shutdown_flag:
                break
            time.sleep(1)
            if last_reconnect + 60 < time.time():
                last_reconnect = time.time()
                fs.close()
                fs = tubes.remote.connect(FLAG_SUBMISSION[0], FLAG_SUBMISSION[1])
                got = fs.recvuntil(b'\n\n')
    except Exception as e:
        handle_exception('flag submission', e, True, f'last_response={got}')


def exploit_wrapper(exploit, teambox_ip, flagid):
    def submit_flag(flag, vocal=False):
        if type(flag) is list:
            for f in flag:
                submit_flag(f, vocal)
        else:
            with flag_queue_lock:
                if type(flag) == bytes:
                    flag = flag.decode()
                flag_queue.put((flag, teambox_ip, flagid, datetime.now().strftime('%H:%M:%S'), vocal))

    try:
        connection_semaphore.acquire()
        exploit(teambox_ip, flagid, submit_flag)
    except Exception as e:
        handle_exception('your exploit', e, False, f'teambox_ip={teambox_ip}, flagid={flagid}')
    finally:
        connection_semaphore.release()


# This thread will call the exploits in parallel
def dispatcher_thread(service_name, exploit):
    global do_shutdown_flag
    try:
        last_run = 0
        blocklisted_flagids = set()
        while True:
            if do_shutdown_flag:
                break
            if last_run + 60 > time.time():
                time.sleep(1)
                continue
            last_run = time.time()
            data = get_json()
            flagids_by_team = data["flag_ids"]

            if len(flagids_by_team) == 0:
                print("Attack stage has not started! Using stub data!")
                flagids_by_team = {service_name: {3: ["3b"], 4: ["4a"], 5: ["5c", "5d"]}}
            if service_name != 'NoFlagIdService':
                if service_name not in flagids_by_team:
                    print(f'There is no service with name {service_name}.\n'
                          f'List of available services: {list(flagids_by_team.keys())}')
                    do_shutdown_flag = True
                    return
                flagids_by_team = flagids_by_team[service_name]
                for teamid, flagids in flagids_by_team.items():
                    if int(teamid) in TEAMID_BLOCKLIST:
                        continue
                    teambox_ip = TEAM_BOX_PATTERN.replace('{TEAM_ID}', str(teamid))
                    for flagid in flagids:
                        if flagid in blocklisted_flagids:
                            continue
                        if do_shutdown_flag:
                            break
                        blocklisted_flagids.add(flagid)
                        t1337 = Thread(target=exploit_wrapper, args=(exploit, teambox_ip, flagid))
                        t1337.start()
            else:
                for teamid in data['teams']:
                    if int(teamid) in TEAMID_BLOCKLIST:
                        continue
                    teambox_ip = TEAM_BOX_PATTERN.replace('{TEAM_ID}', str(teamid))
                    t1337 = Thread(target=exploit_wrapper, args=(exploit, teambox_ip, None))
                    t1337.start()
            for i in range(10):
                if do_shutdown_flag:
                    break
                time.sleep(0.5)
    except Exception as e:
        handle_exception('exploit dispatcher', e, True)


def launch(service_name, connection_limit=20, exploit=None):
    """
    Launch the hacking!
    :param service_name: What is the name of your service? Ask somebody if you do not understand what that means.
    :param connection_limit: How many simultaneous connections should be used for exploiting?
    :param exploit: The exploit function that should be called. See template above to see how it should be constructed.
    This function should accept the following.
    teambox_ip: ip of the box that the function should hack
    flagid: id of the flag that should be extracted (task-specific meaning)
    submit_flag: trough this variable you will receive a function that you should call to submit the flag.
    :return: Should not return at all
    """
    global connection_semaphore, do_shutdown_flag

    try:
        print(f'>> semjond started with exploit for {service_name}')
        if exploit is None:
            print("Using my AI powers to create an exploit... This failed! You must supply an exploit by yourself.")
            return
        connection_semaphore = Semaphore(connection_limit)

        t1 = Thread(target=flag_submitter_thread, args=())
        t1.start()
        t2 = Thread(target=dispatcher_thread, args=(service_name, exploit))
        t2.start()

        while True:
            time.sleep(0.5)
            if do_shutdown_flag:
                break
    except Exception as e:
        handle_exception('main thread', e, True)
    finally:
        do_shutdown_flag = True
        print("semjond MAIN THREAD has shutten down")
