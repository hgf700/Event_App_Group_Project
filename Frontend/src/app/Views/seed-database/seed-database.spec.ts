import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SeedDatabase } from './seed-database';

describe('SeedDatabase', () => {
  let component: SeedDatabase;
  let fixture: ComponentFixture<SeedDatabase>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SeedDatabase],
    }).compileComponents();

    fixture = TestBed.createComponent(SeedDatabase);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
