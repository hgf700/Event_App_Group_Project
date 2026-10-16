import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PublicEvents } from './public-events';

describe('PublicEvents', () => {
  let component: PublicEvents;
  let fixture: ComponentFixture<PublicEvents>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PublicEvents],
    }).compileComponents();

    fixture = TestBed.createComponent(PublicEvents);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
