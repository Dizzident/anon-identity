# Demo Application Template

Create a new repository `anon-identity-demo` with this structure:

```
anon-identity-demo/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── IdentityProvider.tsx
│   │   │   ├── UserWallet.tsx
│   │   │   └── ServiceProvider.tsx
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── backend/
│   ├── src/
│   │   ├── routes/
│   │   │   ├── identity.ts
│   │   │   ├── credentials.ts
│   │   │   └── verification.ts
│   │   ├── services/
│   │   │   └── identityService.ts
│   │   └── index.ts
│   └── package.json
├── docker-compose.yml
├── README.md
└── package.json

## Backend package.json

```json
{
  "name": "anon-identity-demo-backend",
  "version": "1.0.0",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "anon-identity": "^1.0.0",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "socket.io": "^4.6.1"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/cors": "^2.8.17",
    "tsx": "^4.7.0",
    "typescript": "^5.3.3"
  }
}
```

## Frontend package.json

```json
{
  "name": "anon-identity-demo-frontend",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.5",
    "socket.io-client": "^4.6.1",
    "@mui/material": "^5.15.3",
    "@emotion/react": "^11.11.3",
    "@emotion/styled": "^11.11.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.48",
    "@types/react-dom": "^18.2.18",
    "@vitejs/plugin-react": "^4.2.1",
    "typescript": "^5.3.3",
    "vite": "^5.0.11"
  }
}
```

## Backend Example (src/index.ts)

```typescript
import express from 'express';
import cors from 'cors';
import { Server } from 'socket.io';
import { createServer } from 'http';
import { 
  IdentityProvider, 
  UserWallet, 
  ServiceProvider,
  RevocationService 
} from 'anon-identity';

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { origin: 'http://localhost:5173' }
});

app.use(cors());
app.use(express.json());

// Initialize services
const idp = await IdentityProvider.create();
const serviceProviders = new Map<string, ServiceProvider>();

// Routes
app.post('/api/issue-credential', async (req, res) => {
  const { userDID, attributes } = req.body;
  
  try {
    const credential = await idp.issueVerifiableCredential(userDID, attributes);
    
    // Emit real-time update
    io.emit('credential-issued', {
      credentialId: credential.id,
      userDID,
      issuer: idp.getDID()
    });
    
    res.json({ credential });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/verify-presentation', async (req, res) => {
  const { presentation, serviceProviderId } = req.body;
  
  let sp = serviceProviders.get(serviceProviderId);
  if (!sp) {
    sp = new ServiceProvider(serviceProviderId, [idp.getDID()]);
    serviceProviders.set(serviceProviderId, sp);
  }
  
  const result = await sp.verifyPresentation(presentation);
  
  io.emit('verification-complete', {
    serviceProviderId,
    success: result.valid
  });
  
  res.json(result);
});

app.post('/api/revoke-credential/:id', async (req, res) => {
  const { id } = req.params;
  
  idp.revokeCredential(id);
  const url = await idp.publishRevocationList();
  
  io.emit('credential-revoked', { credentialId: id });
  
  res.json({ revocationListUrl: url });
});

server.listen(3001, () => {
  console.log('Demo backend running on http://localhost:3001');
});
```

## Frontend Example Component

```tsx
// src/components/IdentityProvider.tsx
import React, { useState } from 'react';
import { 
  Card, 
  CardContent, 
  TextField, 
  Button, 
  Typography 
} from '@mui/material';
import axios from 'axios';

export const IdentityProviderPanel: React.FC = () => {
  const [userDID, setUserDID] = useState('');
  const [givenName, setGivenName] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  
  const issueCredential = async () => {
    try {
      const response = await axios.post('http://localhost:3001/api/issue-credential', {
        userDID,
        attributes: { givenName, dateOfBirth }
      });
      
      console.log('Credential issued:', response.data);
      // Show success notification
    } catch (error) {
      console.error('Failed to issue credential:', error);
    }
  };
  
  return (
    <Card>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Identity Provider
        </Typography>
        
        <TextField
          fullWidth
          label="User DID"
          value={userDID}
          onChange={(e) => setUserDID(e.target.value)}
          margin="normal"
        />
        
        <TextField
          fullWidth
          label="Given Name"
          value={givenName}
          onChange={(e) => setGivenName(e.target.value)}
          margin="normal"
        />
        
        <TextField
          fullWidth
          label="Date of Birth"
          type="date"
          value={dateOfBirth}
          onChange={(e) => setDateOfBirth(e.target.value)}
          margin="normal"
          InputLabelProps={{ shrink: true }}
        />
        
        <Button
          variant="contained"
          color="primary"
          onClick={issueCredential}
          sx={{ mt: 2 }}
        >
          Issue Credential
        </Button>
      </CardContent>
    </Card>
  );
};
```