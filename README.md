# ibvcap
Infiniband verbs packet capture
Don't forget to load nvidia-current-peermem with

```
# modprobe nvidia-current-peermem
```

You migh tlaso need to set IOMMU to passthrough in grub. But maybe not.

```
intel_iommu=on iommu=pt
```

ONce you compile you'll need to run
```
sudo /usr/sbin/setcap cap_net_raw=ep ./capture
```

Setcap bits are not saved on NFS partitions - so you'll need to be an a local disk.

h1. How it works

we use libiverbs to record the data. There's been a fair amout of experimenting to make it work, so the code is a bit of a mess. Useful things to know.

Sharing a single completion queue make improves performance and code readability.  You need one per device.

Multicast stream subscription happens on a per device basis.

If you use the `--save-gpu` option it makes 2 scatter-gather entires per work request. It sends the ethernet + IP + UDP + CODIF header to the CPU buffer and the rest of the payload to the GPU buffer.

Data from different source IP addresses (which are different antennas) are saved to different buffers. That way each antenna buffer has sequential data. No sorting required!

You need to specify `--num-antnennas 6` to get all of them.

Here's a run with 2 devices, 4 multicast streams and 6 antennas. it receivers all the data with 0 data loss. On average it polls 7 times between each packet that arrives.

Use `-v` to show the packet headres.

Use `--format codifhdr` to save files with codif headers to save chris's too

User `--foramt raw` to save raw files

I thin it will save pcap files too, so you can open them in wireshark.

```
(craft)ibvcap$ ./capture --save-gpu --num-antennas 6 --num-devices 2 --num-multicast-groups 4 --num-blocks 1000000
Using GPU device: 0 NVIDIA L40 Supports GPUDirect? No (likely WDDM or not supported)
Available devices:
  ens3f0np0
Device 0: mlx5_0 ens3f0np0
  ens3f1np1
Device 1: mlx5_1 ens3f1np1
  ens6f0np0
Device 2: mlx5_2 ens6f0np0
  ens6f1np1
Device 3: mlx5_3 ens6f1np1
Opening device 0mlx5_0...
Opening device 1mlx5_1...
IP Address: 130.155.178.211
IP Address: 130.155.178.212
IP Address: 130.155.178.213
IP Address: 130.155.178.214
IP Address: 130.155.178.215
IP Address: 130.155.178.216
IP Address: 130.155.178.211
IP Address: 130.155.178.212
IP Address: 130.155.178.213
IP Address: 130.155.178.214
IP Address: 130.155.178.215
IP Address: 130.155.178.216
IP Address: 130.155.178.211
IP Address: 130.155.178.212
IP Address: 130.155.178.213
IP Address: 130.155.178.214
IP Address: 130.155.178.215
IP Address: 130.155.178.216
IP Address: 130.155.178.211
IP Address: 130.155.178.212
IP Address: 130.155.178.213
IP Address: 130.155.178.214
IP Address: 130.155.178.215
IP Address: 130.155.178.216
  ens3f0np0
Joining multicast group 239.17.0.1 on interface 10.0.5.1
Successfully subscribed mlx5_0 to multicast group 239.17.0.1 on port 36001
  ens3f1np1
Joining multicast group 239.17.0.2 on interface 10.0.5.2
Successfully subscribed mlx5_1 to multicast group 239.17.0.2 on port 36002
  ens3f0np0
Joining multicast group 239.17.0.3 on interface 10.0.5.1
Successfully subscribed mlx5_0 to multicast group 239.17.0.3 on port 36003
  ens3f1np1
Joining multicast group 239.17.0.4 on interface 10.0.5.2
Successfully subscribed mlx5_1 to multicast group 239.17.0.4 on port 36004
Total bytes: 829918860552
Total packets: 100014324
Busy wait: 761343980
Average bytes per packet: 8298
Busy wait / packet 7
Num mismatches 0
```