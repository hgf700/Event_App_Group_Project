import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Dashbord } from './dashbord';

describe('Dashbord', () => {
  let component: Dashbord;
  let fixture: ComponentFixture<Dashbord>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Dashbord],
    }).compileComponents();

    fixture = TestBed.createComponent(Dashbord);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
