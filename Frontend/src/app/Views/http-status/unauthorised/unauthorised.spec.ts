import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Unauthorised } from './unauthorised';

describe('Unauthorised', () => {
  let component: Unauthorised;
  let fixture: ComponentFixture<Unauthorised>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Unauthorised],
    }).compileComponents();

    fixture = TestBed.createComponent(Unauthorised);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
