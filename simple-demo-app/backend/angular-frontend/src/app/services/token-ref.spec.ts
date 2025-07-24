import { TestBed } from '@angular/core/testing';

import { TokenRef } from './token-ref';

describe('TokenRef', () => {
  let service: TokenRef;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TokenRef);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
