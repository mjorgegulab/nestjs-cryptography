import React from 'react';
import clsx from 'clsx';

const GenericLabel = () => {
  return (
    <span
      className={clsx(
        'badge',
        'badge--info',
        'font-weight-bold',
        'margin-left--sm',
      )}
    >
      Generic
    </span>
  );
};

export default GenericLabel;
