import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import ApiReference from './reference/ApiReference.jsx';
import '../styles.css';
import './reference/reference.css';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ApiReference />
  </StrictMode>,
);
