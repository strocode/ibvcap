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