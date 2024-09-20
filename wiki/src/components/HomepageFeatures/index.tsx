import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  img: string;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Uses node:crypto',
    img: require('@site/static/img/node_crypto.png').default,
    description: (
      <>
        Under the hood, it uses the native crypto nodejs library.
        So the wheel hasn't been reinvented, it's just been given a layer.
      </>
    ),
  },
  {
    title: 'Uses Argon2',
    img: require('@site/static/img/phc_logo.png').default,
    description: (
      <>
        As a derivation function or password hashing algorithm, it uses
        Argon2. The winner of the PHC Password Hashing Competition.
      </>
    ),
  },
  {
    title: 'High Level API',
    img: require('@site/static/img/gear_api.png').default,
    description: (
      <>
        It offers a high level API so you don't have to worry about using
        a good cryptographic implementation. This library take care of this
      </>
    ),
  },
];

function Feature({title, img, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <img height={150} src={img} />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
