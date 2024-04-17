# eBPF test suite

A small test suite of eBPF programs running at the XDP level for testing the
basics of a XDP-capable driver.

This was written as part of the final project evaluation of the Advanced
Operating Systems course at Politecnico di Milano, a.y. 2023/2024. The other
part of the project is an initial implementation of XDP support for the OpenNIC 
driver, which can be found on my colleagues 
[fork](https://github.com/marcomole00/open-nic-driver/tree/xdp-support).

## What is tested

- Simple program loading
  - `simple` eBPF application
- `XDP_PASS`ing and `XDP_DROP`ping packets
  - `pass_drop` eBPF application
- Echoing back packets with `XDP_TX`
  - `tx` eBPF program
- Redirecting packets with `XDP_REDIRECT`
  - `redirect_iface` eBPF program

Plus other helpers (`udp_log` and `lib/helpers.bash`).

## Building and running

After you made sure that all submodules have been initialized, in the root of
the project run `make`, run the program you need and check the output of the
kernel debug trace/tcpdump/whatever you are using.

Topologies can be emulated by creating `veth` interfaces using the helper shell
functions available in `lib/helpers.bash`.

All eBPF applications take at least one argument, the interface to attach to,
and should be run as root.

## Acknowledgments

Heavy inspiration taken from the eBPF laboratories of the Network Computing
course (code [here](https://github.com/Polimi-NetClasses/058172-network-computing-labs))
and the [project](https://github.com/alexbradd/network-computing-epbf-project-2023)
I did for the same course.

Ideas about what to test have been taken from this 
[presentation](https://people.redhat.com/lbiancon/conference/NetDevConf2020-0x14/add-xdp-on-driver.html)
from RedHat about adding XDP support to a driver.
