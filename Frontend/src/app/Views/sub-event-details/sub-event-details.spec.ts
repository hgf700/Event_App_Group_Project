import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';

import { SubEventDetails } from './sub-event-details';

describe('SubEventDetails', () => {
  let component: SubEventDetails;
  let fixture: ComponentFixture<SubEventDetails>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SubEventDetails],
      providers: [
        provideRouter([]),
        { provide: MAT_DIALOG_DATA, useValue: { eventId: 1 } },
        { provide: MatDialogRef, useValue: { close: () => { } } }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SubEventDetails);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
