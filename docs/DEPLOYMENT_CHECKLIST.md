# Deployment Checklist for projects.thedude.vip

## Phase 5b: Setup projects.thedude.vip web server

### ✅ Completed Steps

1. Created nginx HTTP configuration at `/etc/nginx/sites-available/projects.thedude.vip.http`
2. Created web directory at `/var/www/projects.thedude.vip` on proxy server
3. Enabled nginx site and reloaded configuration

### ⏳ Pending Steps (Requires DNS Update)

#### 1. Add DNS Record

Add the following DNS record to your thedude.vip DNS provider:

```
Type: A
Name: projects
Host: projects.thedude.vip
Value: 23.116.91.66
TTL: 3600 (or automatic)
```

#### 2. Verify DNS Propagation

After adding the DNS record, wait for propagation (usually 5-60 minutes) and verify:

```bash
dig +short projects.thedude.vip A
# Should return: 23.116.91.66
```

#### 3. Obtain SSL Certificate

Once DNS is working:

```bash
ssh proxy "sudo certbot certonly --webroot -w /var/www/projects.thedude.vip -d projects.thedude.vip --non-interactive --agree-tos --email gardner@thedude.vip"
```

#### 4. Create HTTPS nginx Configuration

Create `/etc/nginx/sites-available/projects.thedude.vip` on proxy:

```nginx
server {
    listen 443 ssl;
    server_name projects.thedude.vip;

    root /var/www/projects.thedude.vip;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
        autoindex on;  # Enable directory listing for apt repo
    }

    # Apt repository location
    location /apt/ {
        alias /var/www/projects.thedude.vip/apt/;
        autoindex on;
    }

    ssl_certificate     /etc/letsencrypt/live/projects.thedude.vip/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/projects.thedude.vip/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name projects.thedude.vip;
    return 301 https://$server_name$request_uri;
}
```

#### 5. Enable HTTPS Site

```bash
ssh proxy "
    sudo ln -sf /etc/nginx/sites-available/projects.thedude.vip /etc/nginx/sites-enabled/
    sudo rm /etc/nginx/sites-enabled/projects.thedude.vip.http
    sudo nginx -t
    sudo systemctl reload nginx
"
```

#### 6. Copy Apt Repository to Web Server

```bash
# From administrator server
scp -r ~/apt-repo/* proxy:/tmp/apt-repo-upload/

# On proxy server
ssh proxy "
    sudo mkdir -p /var/www/projects.thedude.vip/apt
    sudo cp -r /tmp/apt-repo-upload/* /var/www/projects.thedude.vip/apt/
    sudo chown -R www-data:www-data /var/www/projects.thedude.vip/apt
    sudo chmod -R 755 /var/www/projects.thedude.vip/apt
    rm -rf /tmp/apt-repo-upload
"
```

#### 7. Test Repository Access

```bash
curl -I https://projects.thedude.vip/apt/Packages
# Should return: 200 OK

curl -s https://projects.thedude.vip/apt/Packages | head -10
# Should show package metadata
```

## Next Steps After Phase 5b

- **Phase 5c**: Create installation webpage with curl script
- **Phase 5d**: Setup GPG signing for packages
- **Phase 6**: Deploy to all servers

## Notes

- The nginx configuration enables `autoindex on` for the apt repository
- SSL certificate will auto-renew via certbot
- Repository files should be world-readable (755 for directories, 644 for files)
