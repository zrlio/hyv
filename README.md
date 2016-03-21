# hyv
A hybrid I/O virtualization framework for RDMA-capable network interfaces

RDMA-capable interconnects, which provide ultra-low latency and high-bandwidth, are increasingly being used in the context of distributed storage and data processing systems. However, the deployment of such systems in virtualized data centers is currently inhibited by the lack of a flexible and high-performance virtualization solution for RDMA network interfaces. Furthermore, state-of-the-art hardware virtualization is complex and takes up a considerable amount of die space.

Traditional network interface cards (NICs) do not have a sufficient form of device isolation to allow direct sharing between virtual machines and thus, network I/O requires supervision by the hypervisor when using software virtualization. However, going through the hypervisor on every I/O operation is expensive.

In contrast, RDMA devides already offer isolation at the level of user-application, which can be directly leveraged for virtualization. To achieve that, RDMA builds on the concept of separation of paths for control and data operations.

HyV (hybrid virtualization) extends this concept from user applications to virtual machines. With this hybrid virtualization architecture, RDMA control operations are virtualized using hypervisor involvement, whereas data operations are set up to bypass the hypervisor completely without the need for hardware virtualization.

HyV does not require rewriting applications for virtualized RDMA as it integrates into the widely used OpenFabrics software stack.

# Reference
Jonas Pfefferle, Patrick Stuedi, Animesh Trivedi, Bernard Metzler, Ionnis Koltsidas, and Thomas R. Gross
"A Hybrid I/O Virtualization Framework for RDMA-capable Network Interfaces"
In Proceedings of the 11th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE '15) 2015.

# Requirements

* Linux 3.13 kernel on host & guest (only tested with this particular version)
* KVM
* Supports 3 RDMA devices:
  * Chelsio T4/T5 (cxgb4)
  * SoftiWARP
  * Mellanox ConnectX1/2/3 (mlx4)

# Directory Structure

├── guest &nbsp;&nbsp;&nbsp;&nbsp;<b>everything that runs in the guest</b>  
│   ├── include &nbsp;&nbsp;&nbsp;&nbsp;<b>common guest includes</b>  
│   ├── provider    &nbsp;&nbsp;&nbsp;&nbsp;<b>guest OFED provider for RDMA devices</b>   
│   │   ├── cxgb4  
│   │   ├── mlx4  
│   │   └── siw2  
│   ├── virtio_hyv    &nbsp;&nbsp;&nbsp;&nbsp;<b>paravirtual guest driver to forward control-path</b>    
│   └── virtio_rdmacm   &nbsp;&nbsp;&nbsp;&nbsp;<b>paravirtual guest driver for connection management</b>    
├── host    &nbsp;&nbsp;&nbsp;&nbsp;<b>everything that runs on the host</b>    
│   ├── vhost_hyv   &nbsp;&nbsp;&nbsp;&nbsp;<b>paravirtual host driver to forward control-path</b>  
│   │   └── mm    &nbsp;&nbsp;&nbsp;&nbsp;<b>memory management/remapping code as described in the referenced paper (not used anymore)</b>   
│   └── vhost_rdmacm    &nbsp;&nbsp;&nbsp;&nbsp;<b>paravirtual host driver for connection management</b>  
├── hypercall   &nbsp;&nbsp;&nbsp;&nbsp;<b>macro library for hypercalls</b>  
├── include   &nbsp;&nbsp;&nbsp;&nbsp;<b>common includes</b>  
└── object_map   &nbsp;&nbsp;&nbsp;&nbsp;<b>dependency object map</b>  


# Compile & run

##On host
1. Install libibverbs and librdmacm
2. Make sure kernel headers are installed (debian: apt-get install kernel-headers)
3. Run make for each host kernel module: ./host/vhost_hyv and ./host/vhost_rdmacm

##Qemu
1. Get qemu source: git clone http://git.qemu.org/qemu.git
2. Apply patch ./guest/qemu_diff.patch
3. Follow these instructions to compile and test: http://wiki.qemu.org/Hosts/Linux#Simple_build_and_test_with_KVM

##Starting the guest
1. Make sure KVM is available and running: 
* modprobe kvm 
* check if /dev/kvm exists
2. Remove all OFED provider modules on host (mlx4_ib, iw_cxgb4, siw2)
3. Load ib_core and vhost modules
4. Load vhost_hyv module
5. Load needed provider modules (order is important!)
6. Load rdma_cm module and vhost_rdmacm module
7. To add RDMA device to VM prepare hyv config file, where each line is GUID of device in format XXXX:XXXX:XXXX:XXXX (note that hyv also supports adding/removing devices to a running VM)
8. Add virtio-hyv and virtio-rdmacm device to VM (qemu) (e.g. "-device virtio-hyv-pci,config_path="./hyv_config" -device virtio-rdmacm-pci")

##In guest
1. Install libibverbs and librdmacm
2. Install OFED user-libraries of devices libmlx4, libcxgb4 or libsiw2
2. Make sure kernel headers are installed
3. Run make for each guest kernel module: ./guest/virtio_hyv and ./guest/virtio_rdmacm
4. Load ib_core and ib_uverbs
5. Load virtio_rdmacm and virtio_hyv
6. Load needed guest provider: virtio_cxgb4, virtmlx4_ib, or virtsiw2
7. Check with ibv_devinfo if setup was successful!


