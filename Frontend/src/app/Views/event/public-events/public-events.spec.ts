
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { of } from 'rxjs';

import { PublicEvents } from './public-events';
import { EventService } from '../../../Services/EventService';
import { getEventDto } from '../../../Dto/getEventDto';

describe('PublicEvents', () => {
  let component: PublicEvents;
  let fixture: ComponentFixture<PublicEvents>;

  const mockEvents = [
    {
      eventId: 1,
      nameOfEvent: 'Summer Festival',
      typeOfEvent: 'Koncert',
      startOfEvent: '2026-08-15T18:00:00',
      city: 'Bielsko-Biała',
    },
    {
      eventId: 2,
      nameOfEvent: 'Music Night',
      typeOfEvent: 'Impreza',
      startOfEvent: '2026-08-20T20:00:00',
      city: 'Katowice',
    },
  ] as unknown as getEventDto[];

  const eventServiceMock = {
    getPublicEvents: vi.fn(),
  };

  beforeEach(async () => {
    vi.clearAllMocks();

    eventServiceMock.getPublicEvents.mockReturnValue(
      of({
        data: mockEvents,
        totalCount: 12,
      }),
    );

    await TestBed.configureTestingModule({
      imports: [PublicEvents],
      providers: [
        {
          provide: EventService,
          useValue: eventServiceMock,
        },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(PublicEvents);
    component = fixture.componentInstance;

    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load the first page on initialization', () => {
    expect(eventServiceMock.getPublicEvents).toHaveBeenCalledWith(1, 4);
  });

  it('should assign events returned by the service', () => {
    expect(component.events).toEqual(mockEvents);
    expect(component.totalItems).toBe(12);
  });

  it('should display the events', () => {
    const element: HTMLElement = fixture.nativeElement;

    expect(element.textContent).toContain('Summer Festival');
    expect(element.textContent).toContain('Music Night');
  });

  it('should update the page index and load the next page', () => {
    component.onPageChange({
      pageIndex: 1,
      pageSize: 4,
      length: 12,
      previousPageIndex: 0,
    });

    expect(component.pageIndex).toBe(1);
    expect(component.pageSize).toBe(4);
    expect(eventServiceMock.getPublicEvents).toHaveBeenLastCalledWith(2, 4);
  });

  it('should handle a change in page size', () => {
    component.onPageChange({
      pageIndex: 0,
      pageSize: 10,
      length: 12,
      previousPageIndex: 0,
    });

    expect(component.pageSize).toBe(10);
    expect(eventServiceMock.getPublicEvents).toHaveBeenLastCalledWith(1, 10);
  });
});
