const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

const prisma = new PrismaClient();

// ============================================================
// DEVICE-FACING ENDPOINTS
// ============================================================

/**
 * GET /api/biopiat-display/v1/playlist?deviceId=XXX
 * Returns playlist for a device with ETag support
 */
exports.getPlaylist = async (req, res) => {
  try {
    const { deviceId } = req.query;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId is required' });
    }

    // Find device and its assigned playlist
    const device = await prisma.displayDevice.findUnique({
      where: { deviceId },
      include: {
        group: {
          include: {
            playlists: {
              where: { active: true },
              include: {
                items: {
                  include: { content: true },
                  orderBy: { order: 'asc' }
                }
              },
              take: 1
            }
          }
        },
        playlist: {
          include: {
            items: {
              include: { content: true },
              orderBy: { order: 'asc' }
            }
          }
        }
      }
    });

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    // Get playlist (device-specific takes priority over group)
    const playlist = device.playlist || device.group?.playlists?.[0];
    
    if (!playlist) {
      return res.status(200).json({
        deviceId,
        playlistId: null,
        version: 0,
        items: []
      });
    }

    // Generate ETag based on playlist version
    const etag = `"${playlist.id}-v${playlist.version}"`;
    
    // Check If-None-Match header
    const clientEtag = req.headers['if-none-match'];
    if (clientEtag === etag) {
      return res.status(304).end();
    }

    // Check for urgent messages
    const urgentMessages = await prisma.displayUrgentMessage.findMany({
      where: {
        OR: [
          { deviceId: device.id },
          { deviceGroupId: device.groupId }
        ],
        expiresAt: { gt: new Date() }
      },
      orderBy: { priority: 'desc' }
    });

    // Format response
    const response = {
      deviceId,
      playlistId: playlist.id,
      version: playlist.version,
      items: playlist.items.map(item => ({
        id: item.id,
        contentId: item.contentId,
        type: item.content.type,
        title: item.content.title,
        body: item.content.body,
        url: item.content.url,
        posterUrl: item.content.posterUrl,
        durationSec: item.durationSec || item.content.durationSec,
        checksum: item.content.checksum,
        mimeType: item.content.mimeType,
        width: item.content.width,
        height: item.content.height
      })),
      urgentMessages: urgentMessages.map(msg => ({
        id: msg.id,
        title: msg.title,
        body: msg.body,
        priority: msg.priority,
        expiresAt: msg.expiresAt
      }))
    };

    res.set('ETag', etag);
    res.set('Cache-Control', 'private, max-age=30');
    res.json(response);

  } catch (error) {
    console.error('Error fetching playlist:', error);
    res.status(500).json({ error: 'Failed to fetch playlist' });
  }
};

/**
 * POST /api/biopiat-display/v1/device/:deviceId/ack
 * Device acknowledges playlist receipt
 */
exports.acknowledgePlaylist = async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { playlistVersion, cachedItems, lastDisplayedContentId, errors, cpuUsage, memoryUsage } = req.body;

    const device = await prisma.displayDevice.findUnique({
      where: { deviceId }
    });

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    // Update device status
    await prisma.displayDevice.update({
      where: { id: device.id },
      data: {
        currentPlaylistVersion: playlistVersion,
        lastSync: new Date(),
        lastSeen: new Date()
      }
    });

    // Log acknowledgment
    await prisma.displayDeviceLog.create({
      data: {
        deviceId: device.id,
        type: 'playlist_ack',
        data: {
          playlistVersion,
          cachedItems: cachedItems?.length || 0,
          lastDisplayedContentId,
          errors,
          cpuUsage,
          memoryUsage
        }
      }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error acknowledging playlist:', error);
    res.status(500).json({ error: 'Failed to acknowledge playlist' });
  }
};

/**
 * POST /api/biopiat-display/v1/device/:deviceId/heartbeat
 * Device heartbeat for online status
 */
exports.deviceHeartbeat = async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { appVersion, screenWidth, screenHeight } = req.body;

    const device = await prisma.displayDevice.findUnique({
      where: { deviceId }
    });

    if (!device) {
      // Auto-register new device
      await prisma.displayDevice.create({
        data: {
          deviceId,
          name: `Device ${deviceId}`,
          appVersion,
          screenWidth,
          screenHeight,
          lastSeen: new Date()
        }
      });
    } else {
      await prisma.displayDevice.update({
        where: { id: device.id },
        data: {
          lastSeen: new Date(),
          appVersion: appVersion || device.appVersion,
          screenWidth: screenWidth || device.screenWidth,
          screenHeight: screenHeight || device.screenHeight
        }
      });
    }

    res.json({ success: true });

  } catch (error) {
    console.error('Error processing heartbeat:', error);
    res.status(500).json({ error: 'Failed to process heartbeat' });
  }
};

// ============================================================
// CONTENT MANAGEMENT (ADMIN)
// ============================================================

exports.listContent = async (req, res) => {
  try {
    const { type, search, limit = 50, offset = 0 } = req.query;
    
    const where = {};
    if (type) where.type = type;
    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { tags: { has: search } }
      ];
    }

    const [content, total] = await Promise.all([
      prisma.displayContent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: parseInt(limit),
        skip: parseInt(offset)
      }),
      prisma.displayContent.count({ where })
    ]);

    res.json({ content, total, limit: parseInt(limit), offset: parseInt(offset) });

  } catch (error) {
    console.error('Error listing content:', error);
    res.status(500).json({ error: 'Failed to list content' });
  }
};

exports.createContent = async (req, res) => {
  try {
    const { type, title, body, url, posterUrl, durationSec, startAt, endAt, priority, tags, checksum, sizeBytes, mimeType, width, height } = req.body;

    if (!type || !title) {
      return res.status(400).json({ error: 'type and title are required' });
    }

    const content = await prisma.displayContent.create({
      data: {
        type,
        title,
        body,
        url,
        posterUrl,
        durationSec: durationSec || 10,
        startAt: startAt ? new Date(startAt) : null,
        endAt: endAt ? new Date(endAt) : null,
        priority: priority || 0,
        tags: tags || [],
        checksum,
        sizeBytes,
        mimeType,
        width,
        height
      }
    });

    res.status(201).json(content);

  } catch (error) {
    console.error('Error creating content:', error);
    res.status(500).json({ error: 'Failed to create content' });
  }
};

exports.updateContent = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const content = await prisma.displayContent.update({
      where: { id },
      data: {
        ...updates,
        updatedAt: new Date()
      }
    });

    res.json(content);

  } catch (error) {
    console.error('Error updating content:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
};

exports.deleteContent = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.displayContent.delete({
      where: { id }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error deleting content:', error);
    res.status(500).json({ error: 'Failed to delete content' });
  }
};

exports.getUploadUrl = async (req, res) => {
  try {
    const { filename, contentType } = req.body;
    
    // Generate a unique key for the file
    const key = `display-content/${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${filename}`;
    
    // In production, generate a signed URL for S3/GCS
    // For now, return a placeholder
    res.json({
      uploadUrl: `https://storage.example.com/upload/${key}`,
      publicUrl: `https://cdn.example.com/${key}`,
      key
    });

  } catch (error) {
    console.error('Error generating upload URL:', error);
    res.status(500).json({ error: 'Failed to generate upload URL' });
  }
};

// ============================================================
// PLAYLIST MANAGEMENT (ADMIN)
// ============================================================

exports.listPlaylists = async (req, res) => {
  try {
    const playlists = await prisma.displayPlaylist.findMany({
      include: {
        items: { include: { content: true } },
        deviceGroup: true,
        device: true
      },
      orderBy: { updatedAt: 'desc' }
    });

    res.json(playlists);

  } catch (error) {
    console.error('Error listing playlists:', error);
    res.status(500).json({ error: 'Failed to list playlists' });
  }
};

exports.createPlaylist = async (req, res) => {
  try {
    const { name, description, deviceGroupId, deviceId } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }

    const playlist = await prisma.displayPlaylist.create({
      data: {
        name,
        description,
        deviceGroupId,
        deviceId,
        version: 1,
        active: false
      }
    });

    res.status(201).json(playlist);

  } catch (error) {
    console.error('Error creating playlist:', error);
    res.status(500).json({ error: 'Failed to create playlist' });
  }
};

exports.getPlaylistById = async (req, res) => {
  try {
    const { id } = req.params;

    const playlist = await prisma.displayPlaylist.findUnique({
      where: { id },
      include: {
        items: {
          include: { content: true },
          orderBy: { order: 'asc' }
        },
        deviceGroup: true,
        device: true
      }
    });

    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }

    res.json(playlist);

  } catch (error) {
    console.error('Error fetching playlist:', error);
    res.status(500).json({ error: 'Failed to fetch playlist' });
  }
};

exports.updatePlaylist = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, active, deviceGroupId, deviceId } = req.body;

    const playlist = await prisma.displayPlaylist.update({
      where: { id },
      data: {
        name,
        description,
        active,
        deviceGroupId,
        deviceId,
        updatedAt: new Date()
      }
    });

    res.json(playlist);

  } catch (error) {
    console.error('Error updating playlist:', error);
    res.status(500).json({ error: 'Failed to update playlist' });
  }
};

exports.deletePlaylist = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.displayPlaylist.delete({
      where: { id }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error deleting playlist:', error);
    res.status(500).json({ error: 'Failed to delete playlist' });
  }
};

exports.publishPlaylist = async (req, res) => {
  try {
    const { id } = req.params;

    const playlist = await prisma.displayPlaylist.update({
      where: { id },
      data: {
        version: { increment: 1 },
        active: true,
        publishedAt: new Date()
      }
    });

    res.json(playlist);

  } catch (error) {
    console.error('Error publishing playlist:', error);
    res.status(500).json({ error: 'Failed to publish playlist' });
  }
};

exports.addPlaylistItem = async (req, res) => {
  try {
    const { id } = req.params;
    const { contentId, durationSec, startAt, endAt } = req.body;

    // Get current max order
    const maxOrder = await prisma.displayPlaylistItem.aggregate({
      where: { playlistId: id },
      _max: { order: true }
    });

    const item = await prisma.displayPlaylistItem.create({
      data: {
        playlistId: id,
        contentId,
        durationSec,
        startAt: startAt ? new Date(startAt) : null,
        endAt: endAt ? new Date(endAt) : null,
        order: (maxOrder._max.order || 0) + 1
      },
      include: { content: true }
    });

    res.status(201).json(item);

  } catch (error) {
    console.error('Error adding playlist item:', error);
    res.status(500).json({ error: 'Failed to add playlist item' });
  }
};

exports.reorderPlaylistItems = async (req, res) => {
  try {
    const { id } = req.params;
    const { itemIds } = req.body;

    // Update order for each item
    await Promise.all(
      itemIds.map((itemId, index) =>
        prisma.displayPlaylistItem.update({
          where: { id: itemId },
          data: { order: index + 1 }
        })
      )
    );

    res.json({ success: true });

  } catch (error) {
    console.error('Error reordering playlist items:', error);
    res.status(500).json({ error: 'Failed to reorder playlist items' });
  }
};

exports.removePlaylistItem = async (req, res) => {
  try {
    const { itemId } = req.params;

    await prisma.displayPlaylistItem.delete({
      where: { id: itemId }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error removing playlist item:', error);
    res.status(500).json({ error: 'Failed to remove playlist item' });
  }
};

// ============================================================
// DEVICE MANAGEMENT (ADMIN)
// ============================================================

exports.listDevices = async (req, res) => {
  try {
    const devices = await prisma.displayDevice.findMany({
      include: { group: true },
      orderBy: { lastSeen: 'desc' }
    });

    // Add online status
    const now = new Date();
    const devicesWithStatus = devices.map(device => ({
      ...device,
      status: device.lastSeen && (now - new Date(device.lastSeen)) < 5 * 60 * 1000 ? 'online' : 'offline'
    }));

    res.json(devicesWithStatus);

  } catch (error) {
    console.error('Error listing devices:', error);
    res.status(500).json({ error: 'Failed to list devices' });
  }
};

exports.registerDevice = async (req, res) => {
  try {
    const { deviceId, name, location, model, screenWidth, screenHeight } = req.body;

    if (!deviceId) {
      return res.status(400).json({ error: 'deviceId is required' });
    }

    const device = await prisma.displayDevice.create({
      data: {
        deviceId,
        name: name || `Device ${deviceId}`,
        location,
        model,
        screenWidth,
        screenHeight
      }
    });

    res.status(201).json(device);

  } catch (error) {
    console.error('Error registering device:', error);
    res.status(500).json({ error: 'Failed to register device' });
  }
};

exports.getDevice = async (req, res) => {
  try {
    const { id } = req.params;

    const device = await prisma.displayDevice.findUnique({
      where: { id },
      include: { group: true, playlist: true }
    });

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json(device);

  } catch (error) {
    console.error('Error fetching device:', error);
    res.status(500).json({ error: 'Failed to fetch device' });
  }
};

exports.updateDevice = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const device = await prisma.displayDevice.update({
      where: { id },
      data: updates
    });

    res.json(device);

  } catch (error) {
    console.error('Error updating device:', error);
    res.status(500).json({ error: 'Failed to update device' });
  }
};

exports.deleteDevice = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.displayDevice.delete({
      where: { id }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error deleting device:', error);
    res.status(500).json({ error: 'Failed to delete device' });
  }
};

// ============================================================
// DEVICE GROUPS (ADMIN)
// ============================================================

exports.listDeviceGroups = async (req, res) => {
  try {
    const groups = await prisma.displayDeviceGroup.findMany({
      include: {
        devices: true,
        playlists: true
      }
    });

    res.json(groups);

  } catch (error) {
    console.error('Error listing device groups:', error);
    res.status(500).json({ error: 'Failed to list device groups' });
  }
};

exports.createDeviceGroup = async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }

    const group = await prisma.displayDeviceGroup.create({
      data: { name, description }
    });

    res.status(201).json(group);

  } catch (error) {
    console.error('Error creating device group:', error);
    res.status(500).json({ error: 'Failed to create device group' });
  }
};

exports.updateDeviceGroup = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;

    const group = await prisma.displayDeviceGroup.update({
      where: { id },
      data: { name, description }
    });

    res.json(group);

  } catch (error) {
    console.error('Error updating device group:', error);
    res.status(500).json({ error: 'Failed to update device group' });
  }
};

exports.deleteDeviceGroup = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.displayDeviceGroup.delete({
      where: { id }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error deleting device group:', error);
    res.status(500).json({ error: 'Failed to delete device group' });
  }
};

exports.addDeviceToGroup = async (req, res) => {
  try {
    const { id } = req.params;
    const { deviceId } = req.body;

    await prisma.displayDevice.update({
      where: { id: deviceId },
      data: { groupId: id }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error adding device to group:', error);
    res.status(500).json({ error: 'Failed to add device to group' });
  }
};

exports.removeDeviceFromGroup = async (req, res) => {
  try {
    const { deviceId } = req.params;

    await prisma.displayDevice.update({
      where: { id: deviceId },
      data: { groupId: null }
    });

    res.json({ success: true });

  } catch (error) {
    console.error('Error removing device from group:', error);
    res.status(500).json({ error: 'Failed to remove device from group' });
  }
};

// ============================================================
// URGENT MESSAGES
// ============================================================

exports.sendUrgentMessage = async (req, res) => {
  try {
    const { title, body, priority, deviceGroupId, deviceId, expiresInMinutes } = req.body;

    if (!title || !body) {
      return res.status(400).json({ error: 'title and body are required' });
    }

    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + (expiresInMinutes || 30));

    const message = await prisma.displayUrgentMessage.create({
      data: {
        title,
        body,
        priority: priority || 10,
        deviceGroupId,
        deviceId,
        expiresAt
      }
    });

    res.status(201).json(message);

  } catch (error) {
    console.error('Error sending urgent message:', error);
    res.status(500).json({ error: 'Failed to send urgent message' });
  }
};

exports.listUrgentMessages = async (req, res) => {
  try {
    const messages = await prisma.displayUrgentMessage.findMany({
      where: {
        expiresAt: { gt: new Date() }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(messages);

  } catch (error) {
    console.error('Error listing urgent messages:', error);
    res.status(500).json({ error: 'Failed to list urgent messages' });
  }
};
