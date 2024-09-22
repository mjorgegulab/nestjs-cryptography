import React from 'react';
import clsx from 'clsx';

const RecommendedLabel = () => {
  return (
    <span
      className={clsx(
        'badge',
        'badge--success',
        'font-weight-bold',
        'margin-left--sm',
      )}
    >
      Recommended
    </span>
  );
};

export default RecommendedLabel;
