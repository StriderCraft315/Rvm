#!/bin/bash

echo "======================================"
echo "    Rvm VPS Control Panel Installer   "
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

# Check if we're in the git repo
if [ ! -f "rvm.py" ] || [ ! -f "license_gen.py" ]; then
    echo "Error: Please run from Rvm git repository directory"
    echo "Files should be in current directory: rvm.py, license_gen.py"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
apt update && apt upgrade -y
apt install -y python3 python3-pip tmate ufw qemu-kvm libvirt-daemon-system libvirt-clients virt-install virt-manager

# Install Python packages
echo "🐍 Installing Python packages..."
pip3 install flask psutil werkzeug

# Configure firewall
echo "🔥 Configuring firewall..."
ufw allow 3000
ufw allow 22
ufw --force enable

# Setup KVM
echo "🖥️  Setting up KVM..."
# Enable nested virtualization (if supported)
echo 'options kvm_intel nested=1' >> /etc/modprobe.d/kvm.conf
echo 'options kvm_amd nested=1' >> /etc/modprobe.d/kvm.conf

# Start and enable libvirt
systemctl enable libvirtd
systemctl start libvirtd

# Add user to libvirt group
usermod -a -G libvirt $SUDO_USER

# Create default storage pool
virsh pool-define-as default dir - - - - /var/lib/libvirt/images
virsh pool-build default
virsh pool-start default
virsh pool-autostart default

# Set up SSH welcome message
echo "💬 Setting up SSH welcome message..."
echo "Welcome to Rvm VPS Control Panel!" > /etc/motd

# Create sites directory if it doesn't exist
mkdir -p sites

echo "======================================"
echo "    Installation Complete!           "
echo "======================================"
echo "To start Rvm:"
echo "  python3 rvm.py"
echo ""
echo "🌐 Access at: http://your-server-ip:3000"
echo "🔐 Default: admin / admin123"
echo "💾 Database: rvm.db"
echo "🖥️  KVM virtualization ready"
echo ""
echo "✅ Optimized Features:"
echo "   📊 Dashboard with Live Stats"
echo "   📁 Complete File Manager"
echo "   ⚙️  Service Manager"
echo "   🔥 UFW Firewall Control"
echo "   🖥️  KVM Virtualization (VM creation & management)"
echo "   💻 Tmate Session Generator"
echo "   ⚡ System Tools"
echo "   👤 User Management"
echo "   🔒 License System"
echo "   ⚙️  Settings & Configuration"
echo "   🚀 Optimized performance with separate HTML files"
echo ""
echo "🔐 License generator: python3 license_gen.py"
echo "======================================"
