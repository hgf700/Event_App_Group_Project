import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UserTickets } from './user-tickets';

describe('UserTickets', () => {
  let component: UserTickets;
  let fixture: ComponentFixture<UserTickets>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UserTickets],
    }).compileComponents();

    fixture = TestBed.createComponent(UserTickets);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
