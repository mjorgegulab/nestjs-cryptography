// src/components/GenerateHexButton.js

import React, { useState } from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

const GenerateHexButton = () => {
  const [hexValue, setHexValue] = useState('');

  const generateSecureHexValues = (size: number) => {
    const array = new Uint8Array(size);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  const handleClick = () => {
    const hex = generateSecureHexValues(32);
    setHexValue(hex);
  };

  return (
    <div className={clsx('text--center')}>
      <button className={clsx('button button--primary button', styles.button)} onClick={handleClick}>
        Generate Hex Values
      </button>
      {hexValue && (
        <div className={styles.result}>
          <code>{hexValue}</code>
        </div>
      )}
    </div>
  );
};

export default GenerateHexButton;
