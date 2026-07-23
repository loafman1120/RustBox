import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import ConfigReference from './reference/ConfigReference.jsx';
import '../styles.css';
import './reference/reference.css';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ConfigReference />
  </StrictMode>,
);
