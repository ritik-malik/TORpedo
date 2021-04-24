import io
from platform import node
import time
import pycurl
import stem.control
from stem.util import term
from random import randrange, sample

# EXIT_FINGERPRINT_IN = 'E34C28D652520D7C8D386EA3958EA924910E647B'
# EXIT_FINGERPRINT_IN_2 = '059208418A85DAEA537027F54AF9DB8A01AFF381'

# EXIT_FINGERPRINT_SG = '5E762A58B1F7FF92E791A1EA4F18695CAC6677CE'
# EXIT_FINGERPRINT_XOR = '00089AB30F240C64687576C3EE8FC93002D9ACA0'

# paths = [EXIT_FINGERPRINT_IN,EXIT_FINGERPRINT_SG]

SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 10  # timeout before we give up on a circuit

def query(url):
#  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.

  output = io.BytesIO()

  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    return "Unable to reach %s (%s)" % (url, exc)


def scan(controller, path):

#  Fetch ipinfo.io/ip through the given path of relays, providing back the IP & time it took.

  print("Trying to build a circuit on this Path...")

  circuit_id = controller.new_circuit(path, await_build = True)

  def attach_stream(stream):
    if stream.status == 'NEW':
      controller.attach_stream(stream.id, circuit_id)

  controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

  try:
    controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us
    start_time = time.time()

    print("\nCONNECTED SUCCESSFULLY!")
    print("\nOutput from IPinfo:")
    print(term.format(query("http://ipinfo.io/ip"), term.Color.CYAN))

    return time.time() - start_time
  finally:
    controller.remove_event_listener(attach_stream)
    controller.reset_conf('__LeaveStreamsUnattached')

###############

nodes = []
relay_fingerprints = []

with stem.control.Controller.from_port() as controller:
  controller.authenticate()


  num = int(input("Enter the number of relays to be used in tor circuit: "))
  x = input("Do you want random relays: [y/n] ")

  if x.lower() == 'y':
    print("\nDownloading Tor Relay information...")

    for desc in controller.get_network_statuses():
      relay_fingerprints.append([desc.nickname, desc.fingerprint, desc.address])

    print("Done!")
    print("\nNow selecting" ,num, "relays randomly from the Tor Relay list...")

    nodes = sample(relay_fingerprints, num)

    print("\nThe following path has been selected:\n")
    
    for i in nodes:
      print(i)

    path = [x[1] for x in nodes]

  elif x.lower() == 'n':
    print("\nEnter the fingerprints of the", num ," Relays manually -\n")

    for i in range(num):
      nodes.append(input("Enter fingerprint: "))

    path = nodes

  else:
    print("Invalid choice!\n")

  try:
    
    print("\nTesting the above path...")

    time_taken = scan(controller, path)
    print('Total time taken => %0.2f seconds' % (time_taken))
  except Exception as exc:
    print('ERROR => %s' % (exc))






