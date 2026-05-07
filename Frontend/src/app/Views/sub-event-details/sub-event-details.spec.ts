import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SubEventDetails } from './sub-event-details';

describe('SubEventDetails', () => {
  let component: SubEventDetails;
  let fixture: ComponentFixture<SubEventDetails>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SubEventDetails],
    }).compileComponents();

    fixture = TestBed.createComponent(SubEventDetails);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
