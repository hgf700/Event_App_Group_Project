import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SeedData } from './seed-data';

describe('SeedData', () => {
  let component: SeedData;
  let fixture: ComponentFixture<SeedData>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SeedData],
    }).compileComponents();

    fixture = TestBed.createComponent(SeedData);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
