# Deploying the Scanner App to Vercel

This document provides instructions for deploying the Scanner application to Vercel.

## Prerequisites

1. A Vercel account (sign up at [vercel.com](https://vercel.com))
2. The Vercel CLI installed (optional, but recommended for testing)
   ```
   npm install -g vercel
   ```

## Deployment Steps

### 1. Clone the repository

```bash
git clone <repository-url>
cd Scanner-port
```

### 2. Login to Vercel (if using CLI)

```bash
vercel login
```

### 3. Deploy to Vercel

#### Option 1: Using Vercel CLI

```bash
vercel
```

Follow the prompts to complete the deployment.

#### Option 2: Using Vercel Dashboard

1. Push your code to GitHub
2. Log in to [Vercel Dashboard](https://vercel.com/dashboard)
3. Click "Import Project"
4. Select "Import Git Repository" and connect to your GitHub account
5. Select the repository and follow the prompts

### 4. Environment Variables

Make sure to set the following environment variables in your Vercel project settings:

- `SUPABASE_URL`: Your Supabase URL
- `SUPABASE_KEY`: Your Supabase API key
- `FLASK_SECRET_KEY`: A secure random string for Flask session encryption

### 5. Limitations on Vercel

Please note that Vercel has some limitations for Python applications:

1. **Serverless Functions**: The application runs as serverless functions, which have:
   - Cold start times
   - Maximum execution duration (10-60 seconds depending on your plan)
   - Limited file system access

2. **Port Scanning**: Due to network restrictions in serverless environments, actual port scanning functionality may be limited. The application might need to be modified to:
   - Use API-based scanning services
   - Implement client-side scanning for local networks only

3. **File Storage**: Vercel doesn't provide persistent file storage. The application has been modified to:
   - Use Supabase for storing scan results
   - Generate files on-demand rather than storing them

## Troubleshooting

If you encounter issues with the deployment:

1. Check the Vercel logs in the dashboard
2. Ensure all environment variables are correctly set
3. Verify that the Python version is set to 3.9 in vercel.json
4. Check that the build script (build.sh) has executable permissions

## Support

For additional help, please open an issue in the GitHub repository. 