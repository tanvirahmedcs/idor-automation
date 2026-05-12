# idor-automation
automation recon
nano ~/hack.sh
chmod +x ~/hack.sh
echo 'alias hack="bash ~/hack.sh"' >> ~/.zshrc
source ~/.zshrc
hack -d example.com
