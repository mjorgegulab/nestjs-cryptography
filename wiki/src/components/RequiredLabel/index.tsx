import React from 'react';
import clsx from 'clsx';

const RequiredLabel = () => {
  return (
    <span className={clsx('badge', 'badge--danger', 'font-weight-bold', 'margin-left--sm')}>
      Required
    </span>
  );
};

export default RequiredLabel;
