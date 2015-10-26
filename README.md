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
